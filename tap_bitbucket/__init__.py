import argparse
import os
import json
import collections
import time
from dateutil import parser
import pytz
import requests
import re
import psutil
import asyncio
import gc
import singer
import singer.bookmarks as bookmarks
import singer.metrics as metrics
import difflib

from .gitlocal import GitLocal

from singer import metadata

session = requests.Session()
logger = singer.get_logger()

repo_cache = {}

REQUIRED_CONFIG_KEYS = ['start_date', 'user_name', 'access_token', 'repository']

KEY_PROPERTIES = {
    'commits': ['commitId'], # This is the SHA
    'pull_requests': ['artifactId'],
    'pull_request_threads': ['id'],
    'refs': ['ref'],
    'commit_files': ['id'],
    'repositories': ['uuid'],
}

API_VESION = "6.0"

class BitBucketException(Exception):
    pass

class BadCredentialsException(BitBucketException):
    pass

class AuthException(BitBucketException):
    pass

class NotFoundException(BitBucketException):
    pass

class BadRequestException(BitBucketException):
    pass

class InternalServerError(BitBucketException):
    pass

class UnprocessableError(BitBucketException):
    pass

class NotModifiedError(BitBucketException):
    pass

class MovedPermanentlyError(BitBucketException):
    pass

class ConflictError(BitBucketException):
    pass

class RateLimitExceeded(BitBucketException):
    pass

ERROR_CODE_EXCEPTION_MAPPING = {
    301: {
        "raise_exception": MovedPermanentlyError,
        "message": "The resource you are looking for is moved to another URL."
    },
    304: {
        "raise_exception": NotModifiedError,
        "message": "The requested resource has not been modified since the last time you accessed it."
    },
    400:{
        "raise_exception": BadRequestException,
        "message": "The request is missing or has a bad parameter."
    },
    401: {
        "raise_exception": BadCredentialsException,
        "message": "Invalid authorization credentials. Please check that your access token is " \
            "correct, has not expired, and has read access to the 'Code' and 'Pull Request Threads' scopes."
    },
    403: {
        "raise_exception": AuthException,
        "message": "User doesn't have permission to access the resource."
    },
    404: {
        "raise_exception": NotFoundException,
        "message": "The resource you have specified cannot be found"
    },
    409: {
        "raise_exception": ConflictError,
        "message": "The request could not be completed due to a conflict with the current state of the server."
    },
    422: {
        "raise_exception": UnprocessableError,
        "message": "The request was not able to process right now."
    },
    429: {
        "raise_exception": RateLimitExceeded,
        "message": "Request rate limit exceeded."
    },
    500: {
        "raise_exception": InternalServerError,
        "message": "An error has occurred at BitBucket's end processing this request."
    },
    502: {
        "raise_exception": InternalServerError,
        "message": "BitBucket's service is not currently available."
    },
    503: {
        "raise_exception": InternalServerError,
        "message": "BitBucket's service is not currently available."
    },
    504: {
        "raise_exception": InternalServerError,
        "message": "BitBucket's service is not currently available."
    },
}

def get_bookmark(state, repo, stream_name, bookmark_key, default_value=None):
    repo_stream_dict = bookmarks.get_bookmark(state, repo, stream_name)
    if repo_stream_dict:
        return repo_stream_dict.get(bookmark_key)
    if default_value:
        return default_value
    return None

def raise_for_error(resp, source, url):
    error_code = resp.status_code
    try:
        response_json = resp.json()
    except Exception:
        response_json = {}

    # TODO: if/when we hook this up to exception tracking, report the URL as metadat rather than as
    # part of the exception message.

    if error_code == 404:
        details = ERROR_CODE_EXCEPTION_MAPPING.get(error_code).get("message")
        message = "HTTP-error-code: 404, Error: {}. Please check that the following URL is valid "\
            "and you have permission to access it: {}".format(details, url)
    else:
        message = "HTTP-error-code: {}, Error: {} Url: {}".format(
            error_code, ERROR_CODE_EXCEPTION_MAPPING.get(error_code, {}) \
            .get("message", "Unknown Error") if response_json == {} else response_json, \
            url)

    exc = ERROR_CODE_EXCEPTION_MAPPING.get(error_code, {}).get("raise_exception", BitBucketException)
    raise exc(message) from None

def calculate_seconds(epoch):
    current = time.time()
    return int(round((epoch - current), 0))

def get_orgs():
    orgs = []
    for response in authed_get_all_pages(
        'orgs',
        f'https://api.bitbucket.org/2.0/user/permissions/workspaces'
    ):
        memberships = response.json()['values']
        for membership in memberships:
            orgs.append(membership['workspace']['slug'])

    return orgs

def get_repos_for_org(org):
    orgRepos = []
    for response in authed_get_all_pages(
        'repositories',
        f'https://api.bitbucket.org/2.0/repositories/{org}'
    ):
        repos = response.json()['values']
        for repo in repos:
            # Preserve the case used for the org name originally
            orgRepos.append(org + '/' + repo['name'])
            repo_cache[repo['full_name']] = repo

    return orgRepos

def set_auth_headers(config, org = None):
    # TODO: support BitBucket app token

    access_token = config['access_token']
    session.headers.update({'authorization': 'token ' + access_token})

    return access_token

# pylint: disable=dangerous-default-value
def authed_get(source, url, headers={}):
    with metrics.http_request_timer(source) as timer:
        response = None
        retryCount = 0
        maxRetries = 3
        while retryCount < maxRetries:
            session.headers.update(headers)
            # Uncomment for debugging
            #logger.info("requesting {}".format(url))
            response = session.request(method='get', url=url)

            if response.status_code == 429:
                retryCount += 1
                time.sleep(retryCount * 60)
                continue

            if response.status_code != 200:
                raise_for_error(response, source, url)

            timer.tags[metrics.Tag.http_status_code] = response.status_code
    
    if response is None:
        raise_for_error(response, source, url)

    return response

def authed_get_all_pages(source, url, headers={}):
    while True:
        r = authed_get(source, url, headers)
        yield r
        if 'next' in r:
            url = r['next']
        else:
            break

def get_abs_path(path):
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), path)

def load_schemas():
    schemas = {}

    for filename in os.listdir(get_abs_path('schemas')):
        path = get_abs_path('schemas') + '/' + filename
        file_raw = filename.replace('.json', '')
        with open(path) as file:
            schema = json.load(file)
            refs = schema.pop("definitions", {})
            if refs:
                singer.resolve_schema_references(schema, refs)
            schemas[file_raw] = schema

    return schemas

class DependencyException(Exception):
    pass

def validate_dependencies(selected_stream_ids):
    errs = []
    msg_tmpl = ("Unable to extract '{0}' data, "
                "to receive '{0}' data, you also need to select '{1}'.")

    for main_stream, sub_streams in SUB_STREAMS.items():
        if main_stream not in selected_stream_ids:
            for sub_stream in sub_streams:
                if sub_stream in selected_stream_ids:
                    errs.append(msg_tmpl.format(sub_stream, main_stream))

    if errs:
        raise DependencyException(" ".join(errs))


def write_metadata(mdata, values, breadcrumb):
    mdata.append(
        {
            'metadata': values,
            'breadcrumb': breadcrumb
        }
    )

def populate_metadata(schema_name, schema):
    mdata = metadata.new()
    #mdata = metadata.write(mdata, (), 'forced-replication-method', KEY_PROPERTIES[schema_name])
    mdata = metadata.write(mdata, (), 'table-key-properties', KEY_PROPERTIES[schema_name])

    for field_name in schema['properties'].keys():
        if field_name in KEY_PROPERTIES[schema_name]:
            mdata = metadata.write(mdata, ('properties', field_name), 'inclusion', 'automatic')
        else:
            mdata = metadata.write(mdata, ('properties', field_name), 'inclusion', 'available')

    return mdata

def get_catalog():
    raw_schemas = load_schemas()
    streams = []

    for schema_name, schema in raw_schemas.items():

        # get metadata for each field
        mdata = populate_metadata(schema_name, schema)

        # create and add catalog entry
        catalog_entry = {
            'stream': schema_name,
            'tap_stream_id': schema_name,
            'schema': schema,
            'metadata' : metadata.to_list(mdata),
            'key_properties': KEY_PROPERTIES[schema_name],
        }
        streams.append(catalog_entry)

    return {'streams': streams}

def verify_repo_access(url_for_repo, repo, config):
    try:
        authed_get("verifying repository access", url_for_repo)
    except NotFoundException:
        # throwing user-friendly error message as it checks token access
        org = config['org']
        user_name = config['user_name']
        reposplit = repo.split('/')
        projectname = reposplit[0]
        reponame = reposplit[1]
        message = "HTTP-error-code: 404, Error: Please check the repository \'{}\' exists in " \
            "project \'{}\' for org \'{}\', and that user \'{}\' has permission to access it." \
            .format(reponame, projectname, org, user_name)
        raise NotFoundException(message) from None

def verify_access_for_repo(config):
    org = config['org']
    per_page = 1
    page = 1

    repositories = list(filter(None, config['repository'].split(' ')))

    for repo in repositories:
        logger.info("Verifying access of repository: %s", repo)
        reposplit = repo.split('/')
        project = reposplit[0]
        project_repo = reposplit[1]

        # https://dev.azure.com/${ORG}/${PROJECTNAME}/_apis/git/repositories/${REPONAME}/commits?searchCriteria.\$top=${PAGESIZE}\&searchCriteria.\$skip=${SKIP}\&api-version=${APIVERSION}
        url_for_repo = "https://dev.azure.com/{}/{}/_apis/git/repositories/{}/commits?" \
            "searchCriteria.$top={}&searchCriteria.$skip={}&api-version={}" \
            .format(org, project, project_repo, per_page, page - 1, API_VESION)

        # Verifying for Repo access
        verify_repo_access(url_for_repo, repo, config)

def do_discover(config):
    verify_access_for_repo(config)
    catalog = get_catalog()
    # dump catalog
    print(json.dumps(catalog, indent=2))

def write_commit_detail(org, project, project_repo, commit, schema, mdata, extraction_time):
    # Fetch the individual commit to obtain parents. This also provides pushes and other
    # properties, but we don't care about those for now.
    for commit_detail in authed_get_all_pages(
        'commits',
        "https://dev.azure.com/{}/{}/_apis/git/repositories/{}/commits/{}?" \
        "api-version={}" \
        .format(org, project, project_repo, commit['commitId'], API_VESION)
    ):
        detail_json = commit_detail.json()
        commit['parents'] = detail_json['parents']

    # We no longer want to fetch changes here and instead will do it with GitLocal

    commit['_sdc_repository'] = "{}/{}/_git/{}".format(org, project, project_repo)
    with singer.Transformer() as transformer:
        rec = transformer.transform(commit, schema, metadata=metadata.to_map(mdata))
    singer.write_record('commits', rec, time_extracted=extraction_time)

def get_all_commits(schema, repo_path, state, mdata, start_date):
    '''
    https://docs.microsoft.com/en-us/rest/api/azure/devops/git/commits/get-commits?view=azure-devops-rest-6.0#gitcommitref

    Note: the change array looks like it is only included if the query has one result. So, it will
    nee to be fetched with commits/changes in a separate request in most cases.
    '''
    # This will only be use if it's our first run and we don't have any fetchedCommits. See below.
    bookmark = get_bookmark(state, repo_path, "commits", "since", start_date)
    if not bookmark:
        bookmark = '1970-01-01'

    # Get the set of all commits we have fetched previously
    fetchedCommits = get_bookmark(state, repo_path, "commits", "fetchedCommits")
    if not fetchedCommits:
        fetchedCommits = {}
    else:
        # We have run previously, so we don't want to use the time-based bookmark becuase it could
        # skip commits that are pushed after they are committed. So, reset the 'since' bookmark back
        # to the beginning of time and rely solely on the fetchedCommits bookmark.
        bookmark = '1970-01-01'

    # We don't want newly fetched commits to update the state if we fail partway through, because
    # this could lead to commits getting marked as fetched when their parents are never fetched. So,
    # copy the dict.
    fetchedCommits = fetchedCommits.copy()
    # Maintain a list of parents we are waiting to see
    missingParents = {}

    with metrics.record_counter('commits') as counter:
        extraction_time = singer.utils.now()
        iterate_state = {'not': 'empty'}
        count = 1
        while True:
            count += 1
            response = authed_get_all_pages(
                'commits',
                "https://api.bitbucket.org/2.0/repositories/{}/commits?" \
                "api-version={}&searchCriteria.fromDate={}" \
                .format(repo_path, API_VESION, bookmark),
                'searchCriteria.$top',
                'searchCriteria.$skip',
                iterate_state=iterate_state
            )

            commits = list(response)[0].json()
            for commit in commits['value']:
                # Skip commits we've already imported
                if commit['commitId'] in fetchedCommits:
                    continue
                # Will also populate the 'parents' sha list
                write_commit_detail(org, project, project_repo, commit, schema, mdata, extraction_time)

                # Record that we have now fetched this commit
                fetchedCommits[commit['commitId']] = 1
                # No longer a missing parent
                missingParents.pop(commit['commitId'], None)

                # Keep track of new missing parents
                for parent in commit['parents']:
                    if not parent in fetchedCommits:
                        missingParents[parent] = 1

                counter.increment()

            # If there are no missing parents, then we are done prior to reaching the lst page
            if not missingParents:
                break
            # Else if we have reached the end of our data but not found the parents, then we have a
            # problem
            elif iterate_state['stop']:
                raise BitBucketException('Some commit parents never found: ' + \
                    ','.join(missingParents.keys()))
            # Otherwise, proceed to fetch the next page with the next iteration state

    # Don't write until the end so that we don't record fetchedCommits if we fail and never get
    # their parents.
    singer.write_bookmark(state, repo_path, 'commits', {
        'since': singer.utils.strftime(extraction_time),
        'fetchedCommits': fetchedCommits
    })

    return state


def get_commit_detail_local(commit, gitLocalRepoPath, gitLocal):
    try:
        changes = gitLocal.getCommitDiff(gitLocalRepoPath, commit['sha'])
        commit['files'] = changes
    except Exception as e:
        # This generally shouldn't happen since we've already fetched and checked out the head
        # commit successfully, so it probably indicates some sort of system error. Just let it
        # bubbl eup for now.
        raise e

def get_commit_changes(commit, gitLocalRepoPath, gitLocal):
    get_commit_detail_local(commit, gitLocalRepoPath, gitLocal)
    commit['_sdc_repository'] = gitLocalRepoPath
    commit['id'] = '{}/{}'.format(gitLocalRepoPath, commit['sha'])
    return commit

async def getChangedfilesForCommits(commits, gitLocalRepoPath, gitLocal):
    coros = []
    for commit in commits:
        changesCoro = asyncio.to_thread(get_commit_changes, commit, gitLocalRepoPath, gitLocal)
        coros.append(changesCoro)
    results = await asyncio.gather(*coros)
    return results

def get_all_heads_for_commits(repo_path):
    # TODO: implement this for like we did for gitlab
    '''
    Gets a list of all SHAs to use as heads for importing lists of commits. Includes all branches
    and PRs (both base and head) as well as the main branch to get all potential starting points.

    default_branch_name = get_repo_metadata(repo_path)['default_branch']

    # If this data has already been populated with get_all_branches, don't duplicate the work.
    if not repo_path in BRANCH_CACHE:
        cur_cache = {}
        BRANCH_CACHE[repo_path] = cur_cache
        for response in authed_get_all_pages(
            'branches',
            'https://api.github.com/repos/{}/branches?per_page=100'.format(repo_path)
        ):
            branches = response.json()
            for branch in branches:
                isdefault = branch['name'] == default_branch_name
                cur_cache[branch['name']] = {
                    'sha': branch['commit']['sha'],
                    'isdefault': isdefault,
                    'name': branch['name']
                }

    if not repo_path in PR_CACHE:
        cur_cache = {}
        PR_CACHE[repo_path] = cur_cache
        for response in authed_get_all_pages(
            'pull_requests',
            'https://api.github.com/repos/{}/pulls?per_page=100&state=all'.format(repo_path)
        ):
            pull_requests = response.json()
            for pr in pull_requests:
                pr_num = pr.get('number')
                cur_cache[str(pr_num)] = {
                    'pr_num': str(pr_num),
                    'base_sha': pr['base']['sha'],
                    'base_ref': pr['base']['ref'],
                    'head_sha': pr['head']['sha'],
                    'head_ref': pr['head']['ref']
                }

    # Now build a set of all potential heads
    head_set = {}
    for key, val in BRANCH_CACHE[repo_path].items():
        head_set[val['sha']] = 'refs/heads/' + val['name']
    for key, val in PR_CACHE[repo_path].items():
        head_set[val['head_sha']] = 'refs/pull/' + val['pr_num'] + '/head'
        # There could be a PR into a branch that has since been deleted and this is our only record
        # of its head, so include it
        head_set[val['base_sha']] = 'refs/heads/' + val['base_ref']
    return head_set
    '''

def get_all_commit_files(schemas, repo_path, state, mdata, start_date, gitLocal, heads):
    bookmark = get_bookmark(state, repo_path, "commit_files", "since", start_date)
    if not bookmark:
        bookmark = '1970-01-01'

    # Get the set of all commits we have fetched previously
    fetchedCommits = get_bookmark(state, repo_path, "commit_files", "fetchedCommits")
    if not fetchedCommits:
        fetchedCommits = {}
    else:
        # We have run previously, so we don't want to use the time-based bookmark becuase it could
        # skip commits that are pushed after they are committed. So, reset the 'since' bookmark back
        # to the beginning of time and rely solely on the fetchedCommits bookmark.
        bookmark = '1970-01-01'

    logger.info('Found {} fetched commits in state.'.format(len(fetchedCommits)))

    # We don't want newly fetched commits to update the state if we fail partway through, because
    # this could lead to commits getting marked as fetched when their parents are never fetched. So,
    # copy the dict.
    fetchedCommits = fetchedCommits.copy()

    # Get all of the branch heads to use for querying commits
    #heads = get_all_heads_for_commits(repo_path)
    # TODO: get this from syncing branches, similar to gitlab?
    localHeads = gitLocal.getAllHeads(repo_path)
    for k in heads:
        localHeads[k] = heads[k]
    heads = localHeads

    # Set this here for updating the state when we don't run any queries
    extraction_time = singer.utils.now()

    count = 0
    # The large majority of PRs are less than this many commits
    LOG_PAGE_SIZE = 10000
    with metrics.record_counter('commit_files') as counter:
        # First, walk through all the heads and queue up all the commits that need to be imported
        commitQ = []

        for headRef in heads:
            count += 1
            if count % 10 == 0:
                process = psutil.Process(os.getpid())
                logger.info('Processed heads {}/{}, {} bytes'.format(count, len(heads),
                    process.memory_info().rss))
            headSha = heads[headRef]

            # Emit the ref record as well if it's not for a pull request
            if not ('refs/pull' in headRef):
                refRecord = {
                    '_sdc_repository': gitLocalRepoPath,
                    'ref': headRef,
                    'sha': headSha
                }
                with singer.Transformer() as transformer:
                    rec = transformer.transform(refRecord, schemas['refs'],
                        metadata=metadata.to_map(mdata))
                singer.write_record('refs', rec, time_extracted=extraction_time)

            # If the head commit has already been synced, then skip.
            if headSha in fetchedCommits:
                #logger.info('Head already fetched {} {}'.format(headRef, headSha))
                continue

            # Maintain a list of parents we are waiting to see
            missingParents = {}

            # Verify that this commit exists in our mirrored repo
            commitHasLocal = gitLocal.hasLocalCommit(gitLocalRepoPath, headSha)
            if not commitHasLocal:
                logger.warning('MISSING REF/COMMIT {}/{}/{}'.format(gitLocalRepoPath, headRef,
                    headSha))
                # Skip this now that we're mirroring everything. We shouldn't have anything that's
                # missing from github's API
                continue


            offset = 0
            while True:
                commits = gitLocal.getCommitsFromHead(gitLocalRepoPath, headSha, limit = LOG_PAGE_SIZE,
                    offset = offset)

                extraction_time = singer.utils.now()
                for commit in commits:
                    # Skip commits we've already imported
                    if commit['sha'] in fetchedCommits:
                        continue

                    commitQ.append(commit)

                    # Record that we have now fetched this commit
                    fetchedCommits[commit['sha']] = 1
                    # No longer a missing parent
                    missingParents.pop(commit['sha'], None)

                    # Keep track of new missing parents
                    for parent in commit['parents']:
                        if not parent['sha'] in fetchedCommits:
                            missingParents[parent['sha']] = 1

                # If there are no missing parents, then we are done prior to reaching the lst page
                if not missingParents:
                    break
                elif len(commits) > 0:
                    offset += LOG_PAGE_SIZE
                # Else if we have reached the end of our data but not found the parents, then we have a
                # problem
                else:
                    raise BitBucketException('Some commit parents never found: ' + \
                        ','.join(missingParents.keys()))
                # Otherwise, proceed to fetch the next page with the next iteration state

        # Now run through all the commits in parallel
        gc.collect()
        process = psutil.Process(os.getpid())
        logger.info('Processing {} commits, mem(mb) {}'.format(len(commitQ),
            process.memory_info().rss / (1024 * 1024)))

        # Run in batches
        i = 0
        BATCH_SIZE = 16
        PRINT_INTERVAL = 16
        totalCommits = len(commitQ)
        finishedCount = 0

        while len(commitQ) > 0:
            # Slice off the queue to avoid memory leaks
            curQ = commitQ[0:BATCH_SIZE]
            commitQ = commitQ[BATCH_SIZE:]
            changedFileList = asyncio.run(getChangedfilesForCommits(curQ, gitLocalRepoPath, gitLocal))
            for commitfiles in changedFileList:
                with singer.Transformer() as transformer:
                    rec = transformer.transform(commitfiles, schemas['commit_files'],
                        metadata=metadata.to_map(mdata))
                counter.increment()
                singer.write_record('commit_files', rec, time_extracted=extraction_time)

            finishedCount += BATCH_SIZE
            if i % (BATCH_SIZE * PRINT_INTERVAL) == 0:
                curQ = None
                changedFileList = None
                gc.collect()
                process = psutil.Process(os.getpid())
                logger.info('Imported {}/{} commits, {}/{} MB'.format(finishedCount, totalCommits,
                    process.memory_info().rss / (1024 * 1024),
                    process.memory_info().data / (1024 * 1024)))


    # Don't write until the end so that we don't record fetchedCommits if we fail and never get
    # their parents.
    singer.write_bookmark(state, repo_path, 'commit_files', {
        'since': singer.utils.strftime(extraction_time),
        'fetchedCommits': fetchedCommits
    })

    return state


def get_threads_for_pr(prid, schema, org, repo_path, state, mdata):
    '''
    https://docs.microsoft.com/en-us/rest/api/azure/devops/git/pull-request-threads/pull-request-threads-list?view=azure-devops-rest-6.0

    WARNING: This API has no paging support whatsoever, so hope that there aren't any limits.
    '''
    reposplit = repo_path.split('/')
    project = reposplit[0]
    project_repo = reposplit[1]

    for response in authed_get_all_pages(
            'pull_request_threads',
            "https://dev.azure.com/{}/{}/_apis/git/repositories/{}/pullrequests/{}/threads?" \
            "api-version={}" \
            .format(org, project, project_repo, prid, API_VESION)
    ):
        threads = response.json()
        for thread in threads['value']:
            thread['_sdc_repository'] = "{}/{}/_git/{}".format(org, project, project_repo)
            thread['_sdc_pullRequestId'] = prid
            with singer.Transformer() as transformer:
                rec = transformer.transform(thread, schema, metadata=metadata.to_map(mdata))
            yield rec

        # I'm honestly not sure what the purpose is of this, but it was in the github tap
        return state


def get_pull_request_heads(org, repo_path):
    reposplit = repo_path.split('/')
    project = reposplit[0]
    project_repo = reposplit[1]
    
    heads = {}

    for response in authed_get_all_pages(
            'pull_requests',
            "https://dev.azure.com/{}/{}/_apis/git/repositories/{}/pullrequests?" \
            "api-version={}&searchCriteria.status=all" \
            .format(org, project, project_repo, API_VESION),
            '$top',
            '$skip',
            True # No link header to indicate availability of more data
    ):
        prs = response.json()['value']
        for pr in prs:
            prNumber = pr['pullRequestId']
            heads['refs/pull/{}/head'.format(prNumber)] = pr['lastMergeSourceCommit']['commitId']
            if pr.get('lastMergeCommit'):
                heads['refs/pull/{}/merge'.format(prNumber)] = pr['lastMergeCommit']['commitId']
    return heads

def get_all_pull_requests(schemas, org, repo_path, state, mdata, start_date):
    '''
    https://docs.microsoft.com/en-us/rest/api/azure/devops/git/pull-requests/pull-requests-get-pull-requests?view=azure-devops-rest-6.1

    Note: commits will need to be fetched separately in a request to list PR commits
    '''
    reposplit = repo_path.split('/')
    project = reposplit[0]
    project_repo = reposplit[1]

    bookmark = get_bookmark(state, repo_path, "pull_requests", "since", start_date)
    if not bookmark:
        bookmark = '1970-01-01'
    bookmarkTime = parser.parse(bookmark)
    if bookmarkTime.tzinfo is None:
        bookmarkTime = pytz.UTC.localize(bookmarkTime)

    with metrics.record_counter('pull_requests') as counter:
        extraction_time = singer.utils.now()
        for response in authed_get_all_pages(
                'pull_requests',
                "https://dev.azure.com/{}/{}/_apis/git/repositories/{}/pullrequests?" \
                "api-version={}&searchCriteria.status=all" \
                .format(org, project, project_repo, API_VESION),
                '$top',
                '$skip',
                True # No link header to indicate availability of more data
        ):
            prs = response.json()['value']
            for pr in prs:
                # Since there is no fromDate parameter in the API, just filter out PRs that have been
                # closed prior to the the starting time
                if 'closedDate' in pr and parser.parse(pr['closedDate']) < bookmarkTime:
                    continue

                prid = pr['pullRequestId']

                # List the PR commits to include those
                pr['commits'] = []
                for pr_commit_response in authed_get_all_pages(
                        'pull_requests/commits',
                        "https://dev.azure.com/{}/{}/_apis/git/repositories/{}/pullrequests/{}/commits?" \
                        "api-version={}" \
                        .format(org, project, project_repo, prid, API_VESION),
                        '$top',
                        'continuationToken'
                ):
                    pr_commits = pr_commit_response.json()
                    pr['commits'].extend(pr_commits['value'])

                    # Note: These commits will already have their detail fetched by the commits
                    # endpoint (even if they are in an unmerged PR or abandoned), so we don't need
                    # to fetch more info here -- we only need to provide the shallow references.

                # Write out the pull request info

                pr['_sdc_repository'] = "{}/{}/_git/{}".format(org, project, project_repo)

                # So pullRequestId isn't actually unique. There is a 'artifactId' parameter that is
                # unique, but, surprise surprise, the API doesn't actually include this property
                # when listing multiple PRs, so we need to construct it from the URL. Hilariously,
                # this ID also contains %2f for the later slashes instead of actual slashes.
                # Get the project_id and repo_id from the URL
                # TODO: not sure what type of exception to throw here if if the url isn't present
                # and matching this format.
                url_search = re.search('dev\\.azure\\.com/\w+/([-\w]+)/_apis/git/repositories/([-\w]+)', pr['url'])
                project_id = url_search.group(1)
                repo_id = url_search.group(2)
                pr['artifactId'] = "vstfs:///Git/PullRequestId/{}%2f{}%2f{}" \
                    .format(project_id, repo_id, prid)

                with singer.Transformer() as transformer:
                    rec = transformer.transform(pr, schemas['pull_requests'], metadata=metadata.to_map(mdata))
                singer.write_record('pull_requests', rec, time_extracted=extraction_time)
                singer.write_bookmark(state, repo_path, 'pull_requests', {'since': singer.utils.strftime(extraction_time)})
                counter.increment()

                # sync pull_request_threads if that schema is present
                if schemas.get('pull_request_threads'):
                    for thread_rec in get_threads_for_pr(prid, schemas['pull_request_threads'], org, repo_path, state, mdata):
                        singer.write_record('pull_request_threads', thread_rec, time_extracted=extraction_time)
                        singer.write_bookmark(state, repo_path, 'pull_request_threads', {'since': singer.utils.strftime(extraction_time)})

    return state

def get_all_repositories(schema, org, repo_path, state, mdata, start_date):
    # Don't bookmark this one for now
    
    with metrics.record_counter('pull_requests') as counter:
        extraction_time = singer.utils.now()

        for response in authed_get_all_pages(
            'repositories',
            "/2.0/repositories/{workspace}".format(org, API_VESION),
            '$top',
            '$skip',
            True # No link header to indicate availability of more data
        ):
            projects = response.json()['value']
            for project in projects:
                projectName = project['name']
                for response in authed_get_all_pages(
                    'repositories',
                    "https://dev.azure.com/{}/{}/_apis/git/repositories?" \
                    "api-version={}" \
                    .format(org, projectName, API_VESION),
                    '$top',
                    '$skip',
                    True # No link header to indicate availability of more data
                ):
                    repos = response.json()['value']
                    for repo in repos:
                        repoName = repo['name']
                        repo['_sdc_repository'] = '{}/{}/_git/{}'.format(org, projectName, repoName)
                        
                        with singer.Transformer() as transformer:
                            rec = transformer.transform(repo, schema,
                                metadata=metadata.to_map(mdata))
                        singer.write_record('repositories', rec, time_extracted=extraction_time)
                        counter.increment()
    return state

def get_selected_streams(catalog):
    '''
    Gets selected streams.  Checks schema's 'selected'
    first -- and then checks metadata, looking for an empty
    breadcrumb and mdata with a 'selected' entry
    '''
    selected_streams = []
    for stream in catalog['streams']:
        stream_metadata = stream['metadata']
        if stream['schema'].get('selected', False):
            selected_streams.append(stream['tap_stream_id'])
        else:
            for entry in stream_metadata:
                # stream metadata will have empty breadcrumb
                if not entry['breadcrumb'] and entry['metadata'].get('selected',None):
                    selected_streams.append(stream['tap_stream_id'])

    return selected_streams

def get_stream_from_catalog(stream_id, catalog):
    for stream in catalog['streams']:
        if stream['tap_stream_id'] == stream_id:
            return stream
    return None

SYNC_FUNCTIONS = {
    'commits': get_all_commits,
    'commit_files': get_all_commit_files,
    'pull_requests': get_all_pull_requests,
    'repositories': get_all_repositories,
}

SUB_STREAMS = {
    'pull_requests': ['pull_request_threads'],
    'commit_files': ['refs']
}

def do_sync(config, state, catalog):
    global process_globals

    start_date = config['start_date'] if 'start_date' in config else None
    process_globals = config['process_globals'] if 'process_globals' in config else True

    logger.info('Process globals = {}'.format(str(process_globals)))

    # get selected streams, make sure stream dependencies are met
    selected_stream_ids = get_selected_streams(catalog)
    validate_dependencies(selected_stream_ids)

    # Expand */* into the full list of orgs (e.g minwareco/*, otherorg/*)
    if config['repository'] == '*/*':
        if not config['access_token'] or len(config['access_token']) == 0:
            raise Exception('Cannot use org wildcard without a PAT (access_token).')
        access_token = set_auth_headers(config)
        repositories = list()
        orgs = get_orgs()
        for org in orgs:
            repositories.append(f'{org}/*')
    else:
        repositories = list(filter(None, config['repository'].split(' ')))

    # Expand org/*
    allRepos = []
    for repo in repositories:
        repoSplit = repo.split('/')
        if repoSplit[1] == '*':
            org = repoSplit[0]
            access_token = set_auth_headers(config, org)
            orgRepos = get_repos_for_org(repoSplit[0])
            allRepos.extend(orgRepos)
        else:
            allRepos.append(repo)

    domain = config['pull_domain'] if 'pull_domain' in config else 'bitbucket.org'
    gitLocal = GitLocal({
        'access_token': config['access_token'],
        'workingDir': '/tmp',
    }, 'https://{}@' + domain + '/{}', # repo is format: {org}/{repo}
        config['hmac_token'] if 'hmac_token' in config else None)

    #pylint: disable=too-many-nested-blocks
    for repo in allRepos:
        logger.info("Starting sync of repository: %s", repo)
        continue

        org = repo.split('/')[0]
        access_token = set_auth_headers(config, org)

        gitLocal = GitLocal({
            'access_token': access_token,
            'workingDir': '/tmp'
            },
            'https://x-access-token:{}@bitbucket.org/{}.git',
            config['hmac_token'] if 'hmac_token' in config else None
        )
        
        for stream in catalog['streams']:
            stream_id = stream['tap_stream_id']
            stream_schema = stream['schema']
            mdata = stream['metadata']

            if stream_id == 'repositories':
                # Only load this once, and only if process_globals is set to true
                if processed_repositories or not process_globals:
                    continue
                processed_repositories = True

            # if it is a "sub_stream", it will be sync'd by its parent
            if not SYNC_FUNCTIONS.get(stream_id):
                continue

            # if stream is selected, write schema and sync
            if stream_id in selected_stream_ids:
                singer.write_schema(stream_id, stream_schema, stream['key_properties'])

                # get sync function and any sub streams
                sync_func = SYNC_FUNCTIONS[stream_id]
                sub_stream_ids = SUB_STREAMS.get(stream_id, None)

                # sync stream
                if not sub_stream_ids:
                    state = sync_func(stream_schema, repo, state, mdata, start_date)

                # handle streams with sub streams
                else:
                    stream_schemas = {stream_id: stream_schema}

                    # get and write selected sub stream schemas
                    for sub_stream_id in sub_stream_ids:
                        if sub_stream_id in selected_stream_ids:
                            sub_stream = get_stream_from_catalog(sub_stream_id, catalog)
                            stream_schemas[sub_stream_id] = sub_stream['schema']
                            singer.write_schema(sub_stream_id, sub_stream['schema'],
                                                sub_stream['key_properties'])

                    # sync stream and its sub streams
                    if stream_id == 'commit_files':
                        heads = get_pull_request_heads(org, repo)
                        # We don't need to also get open branch heads here becuase those are
                        # included in the git clone --mirror, though PR heads for merged PRs are
                        # not included.
                        state = sync_func(stream_schemas, org, repo, state, mdata, start_date,
                            gitLocal, heads)
                    else:
                        state = sync_func(stream_schemas, org, repo, state, mdata, start_date)

    # The state can get big, don't write it until the end
    singer.write_state(state)

@singer.utils.handle_top_exception(logger)
def main():
    args = singer.utils.parse_args(REQUIRED_CONFIG_KEYS)

    # Initialize basic auth
    user_name = args.config['user_name']
    access_token = args.config['access_token']
    session.auth = (user_name, access_token)

    if args.discover:
        do_discover(args.config)
    else:
        catalog = args.properties if args.properties else get_catalog()
        do_sync(args.config, args.state, catalog)

if __name__ == '__main__':
    main()
