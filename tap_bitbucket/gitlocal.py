# TODO: consolidate this with other copies:
# https://minware.atlassian.net/browse/MW-258

import subprocess
import os
import singer
import hashlib

from io import TextIOWrapper

class GitLocalException(Exception):
  pass

logger = singer.get_logger()

# Average 2^(8 * 8 / 2) = 2^32 items required to experience random collision. Collisions don't
# matter that much in this context, so this should be more than ample length. It is almost better to
# not have too many bits in this scenario, because it makes it harder to reliably reverse the
# actual original code due to there being a lot more possibilities
saveHashLen = 8
# Save on CPU time since we are processing a lot of lines, and the lower bit length described above
# reduces the need for making the hmac difficult to reverse.
hmacIterations = 1

def computeHmac(str, hmacToken):
  if len(str) == 0:
    return str
  else:
    hashObject = hashlib.pbkdf2_hmac('sha256', str.encode('utf8'), hmacToken.encode('utf8'),
      hmacIterations, saveHashLen)
    return hashObject.hex()

def hashPatchLine(patchLine, hmacToken = None):
  if patchLine[0] == '@':
    lineSplit = patchLine.split('@@')
    header = '@@'.join(lineSplit[:2])
    context = '@@'.join(lineSplit[2:])
    if len(context) == 0:
      return patchLine
    else:
      return '@@'.join([header, ' ' + computeHmac(context[1:], hmacToken)])
  else:
    if patchLine == '' or \
        patchLine == '+' or \
        patchLine == '-' or \
        patchLine == '+ ' or \
        patchLine == '- ' or \
        '\\ No newline at end of file' in patchLine:
      return patchLine
    prefix = ''
    if patchLine[0] == '+' or patchLine[0] == '-' or patchLine[0] == ' ':
      prefix = patchLine[0]
      patchLine = patchLine[1:]
    return ''.join([prefix, computeHmac(patchLine, hmacToken)])


def parseDiffLines(lines, shouldEncrypt=False, hmacToken=None):
  MAX_DIFF_LINES=10000
  MAX_PATCH_SIZE=1024 * 1024
  MAX_LINE_LENGTH=500

  changes = []
  curChange = None
  state = 'start'
  for line in lines:
    line = line[0:MAX_LINE_LENGTH-1]

    if '\u0000' in line:
      logger.info('Found unicode NULL byte (U+0000), assuming binary file')
      if curChange:
        curChange['patch'].clear()
        curChange['is_binary'] = True
      else:
        continue

    if len(line) == 0:
      # Only happens on last line -- other blank lines at least start with space
      if curChange:
        changes.append(curChange)
        curChange = None
      continue
    elif line[0:4] == 'diff': # diff
      # Start by assuming file names are the same, and then update later if there's a rename.
      # Unfortunately we can't just do a regex match because " b/" could be in either file name,
      # which would mess stuff up. So, compute the length of the string
      fileNameLen = int((len(line) - len('diff --git a/ b/')) / 2)
      noRenameFname = line[-fileNameLen:]

      # For a pure file mode change, the change type will be none without a patch. Convert this to
      # an edit.
      if curChange and (curChange['changetype'] != 'none' or len(curChange['patch']) > 0 or \
          curChange['is_binary'] or curChange['previous_filename']):
        changes.append(curChange)
      curChange = {
        'filename': noRenameFname,
        'additions': 0,
        'deletions': 0,
        'patch': [],
        'patch_lines': 0,
        'patch_length': 0,
        'previous_filename': '',
        'is_binary': False,
        'is_large_patch': False,
        'changetype': 'none',
      }
      state = 'start'
      pass
    elif state == 'inpatch':
      if curChange['is_binary'] or curChange['is_large_patch']:
        continue

      if line[0] == '@':
        # Note: this line may have context at the end, which is okay and part of the git difff
        # format.
        patchLine = hashPatchLine(line, hmacToken) if shouldEncrypt else line
        curChange['patch'].append(patchLine)
        curChange['patch_lines'] += 1
        curChange['patch_length'] += len(patchLine)
        
        if curChange['patch_lines'] > MAX_DIFF_LINES or curChange['patch_length'] > MAX_PATCH_SIZE:
          curChange['patch'].clear()
          curChange['is_large_patch'] = True
      else:
        if line[0] == '-':
          curChange['deletions'] += 1
        elif line[0] == '+':
          curChange['additions'] += 1
        
        patchLine = hashPatchLine(line, hmacToken) if shouldEncrypt else line
        curChange['patch'].append(patchLine)
        curChange['patch_lines'] += 1
        curChange['patch_length'] += len(patchLine)
        
        if curChange['patch_lines'] > MAX_DIFF_LINES or curChange['patch_length'] > MAX_PATCH_SIZE:
          curChange['patch'].clear()
          curChange['is_large_patch'] = True
    elif line[0] == 'i': # index
      # Ignore file mode changes for now
      pass
    elif line[0] == 's': # similarity index...
      pass
    elif line[0] == 'o': # old mode...
      pass
    elif line[0] == 'n': # new file/mode...
      if line[:8] == 'new mode':
        curChange['changetype'] = 'edit'
      else:
        curChange['changetype'] = 'add'
    elif line[0:3] == 'del': # deleted file
      curChange['changetype'] = 'delete'
    elif line[0] == 'B': # Binary files dffer
      curChange['is_binary'] = True
      pass
    elif line[0] == 'r': # rename from/to...
      if line[0:12] == 'rename from ':
        curChange['previous_filename'] = line[12:]
      elif line[0:10] == 'rename to ':
        curChange['filename'] = line[10:]
    elif line[0] == '-':
      pass # Ignore, will be same as rename from if different from changed file name
    elif line[0] == '+':
      state = 'inpatch'
    else:
      raise GitLocalException('Unexpected line start: "{}"'.format(line))
  for change in changes:
    change['patch'] = '\n'.join(change['patch'])
    if len(change['patch']) == 0:
      change['patch'] = None
    elif len(change['patch']) > 1024 * 1024:
      change['patch'] = None
      change['is_large_patch'] = True

    if (change['is_binary'] or change['is_large_patch'] or change['patch']) \
        and change['changetype'] == 'none':
      change['changetype'] = 'edit'

    # This isn't strictly necessary, but doing it to make sure that the output is exactly the same
    # as when using the API.
    if not change['previous_filename']:
      del change['previous_filename']
    if not change['patch']:
      del change['patch']
  return changes


class GitLocal:
  def __init__(self, config, sourceUrlPattern, hmacToken=None):
    self.token = config['access_token']
    self.workingDir = config['workingDir']
    self.sourceUrlPattern = sourceUrlPattern
    self.hmacToken = hmacToken
    if hmacToken:
      self.shouldEncrypt = True
    else:
      self.shouldEncrypt = False
    self.LS_CACHE = {}
    self.INIT_REPO = {}
    self.rootCommits = {}

  def _getOrgWorkingDir(self, repo):
    orgName = repo.split('/')[0]
    orgWdir = '{}/{}'.format(self.workingDir, orgName)
    if not os.path.exists(orgWdir):
      os.mkdir(orgWdir)
    return orgWdir

  def _getRepoWorkingDir(self, repo):
    orgDir = self._getOrgWorkingDir(repo)
    repoDir = repo.split('/')[-1]
    repoWdir = '{}/{}.git'.format(orgDir, repoDir)
    self._initRepo(repo, repoWdir)
    return repoWdir

  def _cloneRepo(self, repo, repoWdir):
    """
    Clones a repository using git clone, throwing an error if the operation does not succeed
    """
    cloneUrl = self.sourceUrlPattern.format(self.token, repo)
    
    # If directory already exists, do an update
    if os.path.exists(repoWdir):
      logger.info("Updating git remote")

      completed = subprocess.run(['git', 'remote', 'set-url', 'origin', cloneUrl], cwd=repoWdir, capture_output=True)
      if completed.returncode != 0:
        # Don't send the acces token through the error logging system
        strippedOutput = completed.stderr.replace(self.token.encode('utf8'), b'<TOKEN>')
        raise GitLocalException("Updating remote origin of repo {} failed with code {}, message: {}"\
          .format(repo, completed.returncode, strippedOutput))
      
      logger.info("Running git remote update")
      completed = subprocess.run(['git', 'remote', 'update'], cwd=repoWdir, capture_output=True)
      if completed.returncode != 0:
        # Don't send the acces token through the error logging system
        strippedOutput = completed.stderr.replace(self.token.encode('utf8'), b'<TOKEN>')
        raise GitLocalException("Remote update of repo {} failed with code {}, message: {}"\
          .format(repo, completed.returncode, strippedOutput))
    else:
      logger.info('Running git clone for repo {}'.format(repo))
      orgDir = self._getOrgWorkingDir(repo)
      completed = subprocess.run(['git', 'clone', '--mirror', cloneUrl], cwd=orgDir,
        capture_output=True)
      if completed.returncode != 0:
        # Don't send the acces token through the error logging system
        strippedOutput = completed.stderr.replace(self.token.encode('utf8'), b'<TOKEN>')
        raise GitLocalException("Clone of repo {} failed with code {}, message: {}"\
          .format(repo, completed.returncode, strippedOutput))

  def _initRootCommits(self, repo, repoWdir):
    logger.info('Running git rev-list --max-parents=0 --all')
    completed = subprocess.run(['git', 'rev-list', '--max-parents=0', '--all'],
                               cwd=repoWdir, capture_output=True)
    if completed.returncode != 0:
      # Don't send the acces token through the error logging system
      strippedOutput = completed.stderr.replace(self.token.encode('utf8'), b'<TOKEN>')
      raise GitLocalException("Finding root commits of repo {} failed with code {}, message: {}"\
        .format(repo, completed.returncode, strippedOutput))
    
    self.rootCommits[repo] = completed.stdout.decode('utf-8', errors='replace').splitlines()
    logger.info('Root commits for {}, are {}'.format(repo, self.rootCommits[repo]))

  def _initRepo(self, repo, repoWdir):
    if repo in self.INIT_REPO:
      return

    self._cloneRepo(repo, repoWdir)
    self._initRootCommits(repo, repoWdir)

    self.INIT_REPO[repo] = True

  def hasLocalCommit(self, repo, sha, noRetry=False):
    repoDir = self._getRepoWorkingDir(repo)
    completed = subprocess.run(['git', 'cat-file', '-e', sha + '^{commit}'], cwd=repoDir, capture_output=True)
    if completed.returncode == 0:
      return True

    if not noRetry:
      completed = subprocess.run(['git', 'fetch', 'origin', sha], cwd=repoDir, capture_output=True)
      if completed.stderr.decode('utf-8', errors='replace').find('fatal: ') != -1:
        strippedOutput = completed.stderr.replace(self.token.encode('utf8'), b'<TOKEN>')
        raise GitLocalException('Head fetch failed with code {} for repo {}, sha {}, message: {}'\
          .format(completed.returncode, repo, sha, strippedOutput))
      return self.hasLocalCommit(repo, sha, True)
    return False

  def getCommitsFromHead(self, repo, headSha, limit=False, offset=False):
    """
    This function lists multiple commits, but it has a few limitations based on missing data from
    github: (1) it can't fill in the comment count, (2) it doesn't know the github user IDs and
    user names associated wtih the commit.
    """
    repoDir = self._getRepoWorkingDir(repo)
    # Since git log can't escape stuff, create unique sentinals
    startTok = 'xstart5147587x'
    sepTok = 'xsep4983782x'
    params = ['git', 'log', '--pretty={}{}'.format(
      startTok,
      sepTok.join(['%H','%T','%P','%an','%ae','%aI','%cn','%ce','%cI','%B'])
    )]
    if limit:
      params.append('-n{}'.format(int(limit)))
    if offset:
      params.append('--skip={}'.format(int(offset)))
    params.append(headSha)
    completed = subprocess.run(params, cwd=repoDir, capture_output=True)
    if completed.returncode != 0:
      # Don't send the acces token through the error logging system
      strippedOutput = completed.stderr.replace(self.token.encode('utf8'), b'<TOKEN>')
      raise GitLocalException("Log of repo {}, sha {} failed with code {}, message: {}".format(
        repo, headSha, completed.returncode, strippedOutput))
    outstr = completed.stdout.decode('utf8', errors='replace')
    commitLines = outstr.split(startTok)
    commits = []
    for rawCommit in commitLines:
      # Strip off trailing newline as well
      split = rawCommit.rstrip().split(sepTok)
      if len(split) < 2:
        continue
      commits.append({
        '_sdc_repository': repo,
        'sha': split[0],
        'commit': {
          'author': {
            'name': split[3],
            'email': split[4],
            'date': split[5],
          },
          'committer': {
            'name': split[6],
            'email': split[7],
            'date': split[8],
          },
          'tree': {
            'sha': split[1],
          },
          'message': split[9]
          # Omit comment_count, since comments are a github thing
          # Omit 'verification' since we don't care about signatures right now
        },
        # Omit node_id, since we strip it out
        # Author and committer may also exist here in github along with info about github user IDs.
        # We can't include those becuase we don't know them.
        'parents': [] if split[2] == '' else list({
          'sha': p,
        } for p in split[2].split(' ')),
        # Leave stats empty -- it isn't included when listing multiple commits
        # Leave files empty -- it isn't included when listing multiple commits
      })
    return commits

  def _getRootCommits(self, repo):
    return self.rootCommits[repo]

  def getCommitDiff(self, repo, sha):
    """
    Gets detailed information about a commit at a particular sha. This funcion assumes that the
    head has already been fetched and this commit is available.
    """
    repoDir = self._getRepoWorkingDir(repo)
    popenOptions = {
      'cwd': repoDir,
      'stdout': subprocess.PIPE,
      'stderr': subprocess.PIPE
    }
    # 4b825dc642cb6eb9a060e54bf8d69288fbee4904 is the sha of the empty tree
    emptyTree = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
    parentCommit = emptyTree if sha in self._getRootCommits(repo) else sha + '~1'
    logger.debug('running git diff {} {}'.format(parentCommit, sha))
    proc = subprocess.Popen(['git', 'diff', parentCommit, sha], **popenOptions)
    returnCode, stdout, stderr = (proc.returncode, proc.stdout, proc.stderr)

    # give git a second to fail so we can check the return code
    try:
      returnCode = proc.wait(1)
    except:
      pass

    if returnCode is None:
      logger.warn('git diff returnCode is None, unable to check for failure')
    
    if returnCode is not None and returnCode != 0:
      strippedOutput = ''

      if stderr is not None:
        logger.info('stderr')
        strippedOutput = stderr.read().decode('utf-8', errors="replace")
      
      if strippedOutput == '' and stdout is not None:
        logger.info('stdout')
        strippedOutput = stdout.read().decode('utf-8', errors="replace")

      strippedOutput = strippedOutput.replace(self.token, '<TOKEN>')
      raise GitLocalException("Diff of repo {}, sha {} failed with code {}, message: {}".format(
        repo, sha, returnCode, strippedOutput))

    stream = TextIOWrapper(stdout, encoding='utf-8', errors='replace', newline='\n')
    parsed = parseDiffLines(stream, self.shouldEncrypt, self.hmacToken)
    for diff in parsed:
      diff['commit_sha'] = sha

    return parsed

  def getAllHeads(self, repo):
    repoDir = self._getRepoWorkingDir(repo)
    logger.info("Running git show-ref")
    completed = subprocess.run(['git', 'show-ref'], cwd=repoDir, capture_output=True)
    outstr = completed.stdout.decode('utf8', errors='replace')

    # Special case -- first commit, diff instead with an empty tree
    if completed.returncode != 0:
      strippedOutput = '' if not completed.stderr else \
        completed.stderr.replace(self.token.encode('utf8'), b'<TOKEN>')

      # Special failure case: empty repository, just return empty map
      if completed.returncode == 1 and outstr == '' and strippedOutput == '':
        return {}

      raise GitLocalException("show-ref of repo {}, failed with code {}, message: {}".format(
        repo, completed.returncode, strippedOutput))

    headLines = outstr.split('\n')
    headMap = {}
    for line in headLines:
      if len(line) == 0:
        continue
      lineSplit = line.split(' ', 1)
      headSha = lineSplit[0]
      headRef = lineSplit[1]
      headMap[headRef] = headSha

    return headMap
