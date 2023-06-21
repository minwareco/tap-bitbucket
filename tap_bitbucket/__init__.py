import argparse
import os
import json
import copy
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
import urllib.parse
import jwt

from .gitlocal import GitLocal

from singer import metadata

session = requests.Session()
logger = singer.get_logger()

repo_cache = {}

REQUIRED_CONFIG_KEYS = ['start_date', 'user_name', 'access_token', 'repository']
REQUIRED_CONFIG_KEYS_JWT = ['start_date', 'jwt_client_key', 'jwt_shared_secret', 'jwt_subject', 'repository']

KEY_PROPERTIES = {
    'commits': ['id'],
    'commit_files': ['id'],
    'pull_requests': ['id'],
    'pull_request_comments': ['id'],
    'refs': ['ref'],
    'repositories': ['id'],
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
    for memberships in authed_get_all_pages(
        'orgs',
        f'https://api.bitbucket.org/2.0/user/permissions/workspaces'
    ):
        for membership in memberships:
            logger.info("membership = {}".format(json.dumps(membership, indent = 4)))
            orgs.append(membership['workspace']['slug'])

    return orgs

def get_repos_for_org(org):
    orgRepos = []
    for repos in authed_get_all_pages(
        'repositories',
        f'https://api.bitbucket.org/2.0/repositories/{org}?pagelen=100'
    ):
        for repo in repos:
            # Preserve the case used for the org name originally
            orgRepos.append(org + '/' + repo['slug'])
            repo_cache[repo['full_name']] = repo

    return orgRepos

repo_cache = {}
def get_repo_metadata(repo_path):
    if not repo_path in repo_cache:
        response = authed_get(
            'repositories',
            'https://api.bitbucket.org/2.0/repositories/{}'.format(repo_path)
        )
        repo_cache[repo_path] = response
    return repo_cache[repo_path]

# pylint: disable=dangerous-default-value
def authed_post(source, url, data, headers={}):
    logger.info("authed_get URL = {}".format(url))
    with metrics.http_request_timer(source) as timer:
        response = None
        retryCount = 0
        maxRetries = 3
        while response is None and retryCount < maxRetries:
            session.headers.update(headers)
            # Uncomment for debugging
            #logger.info("requesting {}".format(url))
            response = session.post(url, data)

            if response.status_code == 429:
                retryCount += 1
                time.sleep(retryCount * 60)
                continue

            if response.status_code != 200:
                raise_for_error(response, source, url)

            timer.tags[metrics.Tag.http_status_code] = response.status_code

    if response is None:
        raise_for_error(response, source, url)

    return response.json()

# pylint: disable=dangerous-default-value
def authed_get(source, url, headers={}):
    logger.info("authed_get URL = {}".format(url))
    with metrics.http_request_timer(source) as timer:
        response = None
        retryCount = 0
        maxRetries = 3
        while response is None and retryCount < maxRetries:
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

    return response.json()

def authed_get_all_pages(source, url, headers={}):
    while True:
        r = authed_get(source, url, headers)
        yield r['values']
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
    repositories = list(filter(None, config['repository'].split(' ')))

    for repo in repositories:
        logger.info("Verifying access of repository: %s", repo)
        url_for_repo = "https://api.bitbucket.org/2.0/repositories/{}/commits?".format(repo)

        # Verifying for Repo access
        verify_repo_access(url_for_repo, repo, config)

def do_discover(config):
    # We don't need repo access if we're just dumping the catalog
    #verify_access_for_repo(config)
    catalog = get_catalog()
    # dump catalog
    print(json.dumps(catalog, indent=2))

def sync_all_commits(schema, repo_path, state, mdata, start_date):
    # This will only be used if it's our first run and we don't have any fetchedCommits. See below.
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

    # Maintain a list of parents we are waiting to see
    missingParents = {}

    with metrics.record_counter('commits') as counter:
        extraction_time = singer.utils.now()
        for commits in  authed_get_all_pages(
            'commits',
            "https://api.bitbucket.org/2.0/repositories/{}/commits?pagelen=100".format(repo_path),
        ):
            for commit in commits:
                # Skip commits we've already imported
                if commit['hash'] in fetchedCommits:
                    continue
                commit['_sdc_repository'] = repo_path
                commit['id'] = '{}/{}'.format(repo_path, commit['hash'])
                commit['committer_date'] = commit['date']
                with singer.Transformer() as transformer:
                    rec = transformer.transform(commit, schema, metadata=metadata.to_map(mdata))
                singer.write_record('commits', rec, time_extracted=extraction_time)

                # Record that we have now fetched this commit
                fetchedCommits[commit['hash']] = 1
                # No longer a missing parent
                missingParents.pop(commit['hash'], None)

                # Keep track of new missing parents
                for parent in commit['parents']:
                    if not parent['hash'] in fetchedCommits:
                        missingParents[parent['hash']] = 1
                counter.increment()

    if len(missingParents) > 0:
        raise BitBucketException('Some commit parents never found: ' + ', '.join(missingParents.keys()))

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

def sync_all_commit_files(schemas, org, repo_path, state, mdata, start_date, gitLocal, heads):
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
                    '_sdc_repository': repo_path,
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
            commitHasLocal = gitLocal.hasLocalCommit(repo_path, headSha, True)
            if not commitHasLocal:
                logger.warning('MISSING REF/COMMIT {}/{}/{}'.format(repo_path, headRef, headSha))
                # Skip this now that we're mirroring everything. We shouldn't have anything that's
                # missing from BitBucket's API
                continue


            offset = 0
            while True:
                commits = gitLocal.getCommitsFromHead(repo_path, headSha, limit = LOG_PAGE_SIZE,
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
            changedFileList = asyncio.run(getChangedfilesForCommits(curQ, repo_path, gitLocal))
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

def get_pull_request_heads(repo_path):
    heads = {}
    for prs in authed_get_all_pages(
        'pull_requests',
        'https://api.bitbucket.org/2.0/repositories/{}/pullrequests?'.format(repo_path) + \
            'state=OPEN&state=MERGED&state=DECLINED&state=SUPERSEDED'
    ):
        for pr in prs:
            prNumber = pr['id']
            heads['refs/pull/{}/head'.format(prNumber)] = pr['source']['commit']['hash']
            if pr.get('merge_commit'):
                heads['refs/pull/{}/merge'.format(prNumber)] = pr['merge_commit']['hash']
    return heads

def normalize_pull_request_endpoint(endpoint):
    result = {
        "branch": endpoint['branch']['name'],
        "commit_hash": endpoint['commit']['hash'] if endpoint['commit'] is not None else None,
        "repository": endpoint['repository'] # no transform done
    }
    return result

def sync_all_pull_requests(schemas, org, repo_path, state, mdata, start_date):
    bookmark = get_bookmark(state, repo_path, "pull_requests", "since", start_date)
    if not bookmark:
        bookmark = '1970-01-01'
    bookmarkTime = parser.parse(bookmark)
    if bookmarkTime.tzinfo is None:
        bookmarkTime = pytz.UTC.localize(bookmarkTime)

    with metrics.record_counter('pull_requests') as counter:
        extraction_time = singer.utils.now()
        query = urllib.parse.quote('updated_on>={}'.format(bookmarkTime.isoformat()))
        for prs in authed_get_all_pages(
            'pull_requests',
            'https://api.bitbucket.org/2.0/repositories/{}/pullrequests?'.format(repo_path) + \
                'q={}&sort=updated_on&state=OPEN&state=MERGED&state=DECLINED&state=SUPERSEDED'.format(query)
        ):
            for pr in prs:
                # we have to fetch the PR on its own in order to get the full data payload. notably,
                # participants and reviewers are not included in the response from the original request
                # to list PRs (above)
                pr = authed_get('pull_requests', 'https://api.bitbucket.org/2.0/repositories/{}/pullrequests/{}'.format(repo_path, pr['id']))
                pr['_sdc_repository'] = repo_path
                pr['number'] = pr['id'] # e.g. 1, 13, 65
                pr['id'] = '{}/{}'.format(repo_path, pr['number']) # e.g. minware/repotest/1
                pr['source'] = normalize_pull_request_endpoint(pr['source'])
                pr['destination'] = normalize_pull_request_endpoint(pr['destination'])

                with singer.Transformer() as transformer:
                    rec = transformer.transform(pr, schemas['pull_requests'], metadata=metadata.to_map(mdata))
                singer.write_record('pull_requests', rec, time_extracted=extraction_time)
                counter.increment()

                if schemas.get('pull_request_comments'):
                    sync_all_pull_request_comments(schemas, org, repo_path, pr['id'], pr['number'], state, mdata, start_date)

    singer.write_bookmark(state, repo_path, 'pull_requests', {
        'since': singer.utils.strftime(extraction_time)
    })

    return state

def sync_all_pull_request_comments(schemas, org, repo_path, pr_id, pr_number, state, mdata, start_date):
    # bookmark data is keyed by pr ID, and the value is the date/time of the most recent successful ingest
    bookmark = get_bookmark(state, repo_path, "pull_request_comments", pr_id, start_date)
    if not bookmark:
        bookmark = '1970-01-01'
    bookmarkTime = parser.parse(bookmark)
    if bookmarkTime.tzinfo is None:
        bookmarkTime = pytz.UTC.localize(bookmarkTime)

    with metrics.record_counter('pull_request_comments') as counter:
        extraction_time = singer.utils.now()
        query = urllib.parse.quote('created_on>{}'.format(bookmarkTime.isoformat()))
        for comments in authed_get_all_pages(
            'pull_request_comments',
            'https://api.bitbucket.org/2.0/repositories/{}/pullrequests/{}/comments?'.format(repo_path, pr_number) + \
                'q={}&pagelen=100'.format(query)
        ):
            for comment in comments:
                comment['_sdc_repository'] = repo_path
                comment['id'] = '{}/{}'.format(pr_id, comment['id'])
                comment['pr_id'] = pr_id

                parent = comment.get('parent')
                if parent:
                    parent['id'] = '{}/{}'.format(pr_id, parent['id'])

                with singer.Transformer() as transformer:
                    rec = transformer.transform(comment, schemas['pull_request_comments'], metadata=metadata.to_map(mdata))
                singer.write_record('pull_request_comments', rec, time_extracted=extraction_time)
                counter.increment()

    singer.write_bookmark(state, repo_path, 'pull_request_comments', {
        pr_id: singer.utils.strftime(extraction_time)
    })

    return state

def sync_all_repositories(schema, repo_path, state, mdata, _start_date):
    repo_metadata = get_repo_metadata(repo_path)

    with metrics.record_counter('repositories') as counter:
        extraction_time = singer.utils.now()
        repo = {}
        repo['id'] = 'bitbucket/' + repo_path
        repo['source'] = 'bitbucket'
        repo['org_name'] = repo_path.split('/')[0]
        repo['repo_name'] = repo_path.split('/')[1]
        repo['is_source_public'] = repo_metadata['is_private'] == False
        repo['fork_org_name'] = None # TODO: make `forks` API call to get this
        repo['fork_repo_name'] = None # TODO: make `forks` API call to get this
        repo['description'] = repo_metadata['description']
        repo['default_branch'] = repo_metadata['mainbranch']['name']
        with singer.Transformer() as transformer:
            rec = transformer.transform(repo, schema, metadata=metadata.to_map(mdata))
        singer.write_record('repositories', rec, time_extracted=extraction_time)
        counter.increment()
    return state

def get_selected_streams(catalog):
    '''
    Gets selected streams based on the 'selected' property.
    '''
    selected_streams = []
    for stream in catalog['streams']:
        if stream['schema'].get('selected', False):
            selected_streams.append(stream['tap_stream_id'])

    return selected_streams

def get_stream_from_catalog(stream_id, catalog):
    for stream in catalog['streams']:
        if stream['tap_stream_id'] == stream_id:
            return stream
    return None

SYNC_FUNCTIONS = {
    'commits': sync_all_commits,
    'commit_files': sync_all_commit_files,
    'pull_requests': sync_all_pull_requests,
    'repositories': sync_all_repositories,
}

SUB_STREAMS = {
    'pull_requests': ['pull_request_comments'],
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
            orgRepos = get_repos_for_org(repoSplit[0])
            allRepos.extend(orgRepos)
        else:
            allRepos.append(repo)

    domain = config['pull_domain'] if 'pull_domain' in config else 'bitbucket.org'
    gitLocal = GitLocal({
        'access_token': config["git_access_token"],
        'workingDir': '/tmp',
    }, 'https://{}@' + domain + '/{}', # repo is format: {org}/{repo}
        config['hmac_token'] if 'hmac_token' in config else None)

    #pylint: disable=too-many-nested-blocks
    for repo in allRepos:
        logger.info("Starting sync of repository: %s", repo)

        org = repo.split('/')[0]

        for stream in catalog['streams']:
            stream_id = stream['tap_stream_id']
            stream_schema = stream['schema']
            mdata = stream['metadata']

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
                        heads = get_pull_request_heads(repo)
                        # We don't need to also get open branch heads here becuase those are
                        # included in the git clone --mirror, though PR heads for merged PRs are
                        # not included.
                        state = sync_func(stream_schemas, org, repo, state, mdata, start_date, gitLocal, heads)
                    else:
                        state = sync_func(stream_schemas, org, repo, state, mdata, start_date)

    # The state can get big, don't write it until the end
    singer.write_state(state)

def get_args():
    unchecked_args = singer.utils.parse_args([])
    if 'jwt_client_key' in unchecked_args.config.keys():
        return singer.utils.parse_args(REQUIRED_CONFIG_KEYS_JWT)
    
    return singer.utils.parse_args(REQUIRED_CONFIG_KEYS)

def generate_jwt_token(issuer, subject, secret):
    now = int(time.time())

    encoded_jwt = jwt.encode({
        'iss': issuer,
        # issued at time, 60 seconds in the past to allow for clock drift
        "iat": now,
        "exp": now + (6 * 60 * 60), # timeout in seconds = 6 hours
        "sub": subject
    }, secret, "HS256")
    
    return encoded_jwt

@singer.utils.handle_top_exception(logger)
def main():
    args = get_args()

    config = args.config
    if 'user_name' in args.config:
        # Initialize basic auth
        user_name = args.config['user_name']
        access_token = args.config['access_token']
        session.auth = (user_name, access_token)
        config["git_access_token"] = "{}:{}".format(user_name, access_token)
    elif 'jwt_client_key' in args.config:
        jwt_token = generate_jwt_token(
            args.config['jwt_client_key'],
            args.config['jwt_subject'],
            args.config['jwt_shared_secret'])
        session.headers.update({'authorization': 'JWT ' + jwt_token})
        access_token_response = authed_post(
            'access token request',
            'https://bitbucket.org/site/oauth2/access_token',
            {'grant_type': 'urn:bitbucket:oauth2:jwt'},
            {'Content-Type': 'application/x-www-form-urlencoded'})

        config["git_access_token"] = "x-token-auth:{}".format(access_token_response['access_token'])

    if args.discover:
        do_discover(args.config)
    else:
        catalog = args.properties if args.properties else get_catalog()
        do_sync(args.config, args.state, catalog)

if __name__ == '__main__':
    main()
