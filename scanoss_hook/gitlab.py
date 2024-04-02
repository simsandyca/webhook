# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2017-2020, SCANOSS Ltd. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
#
# Modified by Sandy Sim - Sept 2023

from http.server import BaseHTTPRequestHandler

import base64
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import requests
import re
from urllib import parse
from typing import Any
from .scanner import Scanner

# CONSTANTS
GL_HEADER_TOKEN = 'X-Gitlab-Token'
GL_HEADER_EVENT = 'X-Gitlab-Event'
GL_HEADER_TOTAL_PAGES = 'x-total-pages'

GL_PUSH_EVENT = 'Push Hook'
GL_MERGE_REQUEST_EVENT = 'Merge Request Hook'

# This is a markdown comment that is used to check if this commit has already been scanned.
#  Finding this marker in the commit comment will mean that the commit has already been scanned
SCAN_MARKER = '[comment]: <> (SCANOSS)'

# This markdown comment has a validation flag (true if the commit has open source) and the 
#  raw scan result in json format
STATUS_MARKER = '[comment]: <> ({"validation": "%s", "scan_result": "%s"})'

executor = ThreadPoolExecutor(max_workers=10)

class GitLabAPI:
  """
  Several GitLab API functions

  Attributes
  ----------
  api_key : src
    The GitLab API Key
  base_url : src
    The GitLab API Base URL.

  Methods
  -------
  get_diff_json(project, commit)
    Returns the diff data structure for a commit from GitLab API

  get_commit_diff(project, commit)
    Retrieves the raw diff string for a commit.

  get_commit_refs(project, commit)
    Retrieves the list of refs in which the commit appears.

  get_files_in_commit_diff(project, commit)
    Returns the list of files in a commit diff

  get_commit_comments(project, commit)
    Returns a string with all comments from a commit

  get_json_array(url)
    Return an array of json objects using Gitlab paging 

  """

  def __init__(self, config):
    self.api_key = config['gitlab']['api-key']
    self.base_url = config['gitlab']['api-base']
    self.auth_headers = {'PRIVATE-TOKEN': self.api_key}

  def get_diff_json(self, project, commit):
    request_url = "%s/projects/%d/repository/commits/%s/diff" % (
        self.base_url, project['id'], commit['id'])
    return self.get_json_array(request_url)

  def get_commit_diff(self, project, commit):
    diff_list = self.get_diff_json(project, commit)
    if diff_list:
      diffs = ["--- %s\n+++ %s\n%s" %
               (d['old_path'], d['new_path'], d['diff']) for d in diff_list]
      return '\n'.join(diffs)
    return None

  def get_commit_refs(self, project, commit):
    request_url = "%s/projects/%d/repository/commits/%s/refs" % (
        self.base_url, project['id'], commit['id'])
    return self.get_json_array(request_url)

  def get_files_in_commit_diff(self, project, commit):
    diff_obj = self.get_diff_json(project, commit)
    if diff_obj:
      # We don't care about deleted files
      return [d['new_path'] for d in diff_obj if not d['deleted_file']]
    return None

  def get_commit_comments(self, project, commit):
    request_url = "%s/projects/%d/repository/commits/%s/comments" % (
        self.base_url, project['id'], commit['id'])
    return self.get_json_array(request_url)

  def get_json_array(self, url):
    pg = 1
    tot_page = 1
    json = []

    while pg <= tot_page:
      request_url = "%s?page=%d" % (url, pg)
      r = requests.get(request_url, headers=self.auth_headers)
      if r.status_code != 200:
        logging.error(
            "There was an error trying to obtain url \"%s\", the server returned status %d", url, r.status_code)
        return None
    
      json += r.json()
      tot_page = int(r.headers.get(GL_HEADER_TOTAL_PAGES) or 1)
      pg += 1

    return json

  def post_commit_comment(self, project, commit, comment):
    """ Uses GitLab API to add a new commit comment
    """
    comments_url = "%s/projects/%d/repository/commits/%s/comments" % (
        self.base_url, project['id'], commit['id'])
    logging.debug("Post comment to URL: %s", comments_url)
    r = requests.post(comments_url, json=comment, headers=self.auth_headers)
    if r.status_code >= 400:
      logging.error(
          "There was an error posting a comment for commit, the server returned status %d", r.status_code)

  def get_assets_json_file(self, project, commit, sbom_file):
    return self.get_file_contents(project, commit, sbom_file)

  def get_file_contents(self, project, commit, filename):
    url = "%s/projects/%d/repository/files/%s" % (
        self.base_url, project['id'], parse.quote_plus(filename))
    r = requests.get(url, headers=self.auth_headers,
                     params={"ref": commit["id"]})
    if r.status_code == 200:
      file_json = r.json()
      return base64.b64decode(file_json['content'])
    return None

  def update_build_status(self, project, commit, status=False):
    # POST /projects/:id/statuses/:sha
    logging.debug("Updating build status for commit %s", commit['id'])
    url = "%s/projects/%d/statuses/%s" % (self.base_url,
                                          project['id'], commit['id'])
    data = {"state": "success" if status else "failed"}
    r = requests.post(url, json=data, headers=self.auth_headers)
    if r.status_code >= 400:
      logging.error(
          "There was an error updating build status for commit %s", commit['id'])


class GitLabRequestHandler(BaseHTTPRequestHandler):
  """A GitLab webhook request handler. Handles Webhook events from GitLab

  Attributes
  ----------
  config : dict
    The configuration dictionary

  Methods
  -------
  do_POST()
    Handles the Webhook post event.

  """

  def __init__(self, config, *args: Any) -> None:
    self.config = config
    self.scanner = Scanner(config)
    self.api_key = self.config['gitlab']['api-key']
    self.base_url = self.config['gitlab']['api-base']
    self.api = GitLabAPI(config)
    self.sbom_file = "SBOM.json"
    try: 
      # comment on the commit even if it has no open source matches
      self.comment_always = config['scanoss']['comment_always'] 

      # Only comment on a commit once
      self.comment_once = config['scanoss']['comment_once'] 

      # name of the sbom file
      self.sbom_file = config['scanoss']['sbom_filename']
 
      self.scanoss_url = self.config['scanoss']['url']
      self.scanoss_token = self.config['scanoss']['token']
   
    except Exception: 
      logging.error("There is an error in the scanoss section in the config file")
      
    try: 
      self.fix_file_url = config['webhook']['fix_file_url']
      self.site_url = config['webhook']['site_url']
    except Exception: 
      logging.error("There is an error in the webhook section in the config file")
      
    logging.debug("Starting GitLabRequestHandler with base_url: %s",
                  self.base_url)

    BaseHTTPRequestHandler.__init__(self, *args)

  def do_GET(self):
    """ Handles relaying api gets with scanoss token 

    """
    path = parse.urlparse(self.path).path
    if re.search("^/file_contents/.*", path):
      url = self.scanoss_url + path
      headers = {'X-Session': self.scanoss_token}
      r = requests.get(url, headers=headers)
      if r.status_code == 200:
        self.send_response(200,"OK")
        self.send_header("content-type", "text/plain")
        self.end_headers()
        self.wfile.write(bytes(r.content))
      else: 
        self.send_response(500,"Failed to get file from SCANOSS")
        self.end_headers()
      return

  def do_POST(self):
    """ Handles the webhook post event.

    """
    # We are only interested in push events
    if self.headers.get(GL_HEADER_EVENT) != GL_PUSH_EVENT:
      self.send_response(200, "OK")
      self.end_headers()
      return

    # get payload
    header_length = int(self.headers['Content-Length'])
    # get gitlab secret token

    json_payload = self.rfile.read(header_length)
    json_params = {}
    if len(json_payload) > 0:
      json_params = json.loads(json_payload.decode('utf-8'))

    # If there are no commits, return
    commits = json_params.get("commits")
    if not commits:
      self.send_response(200, "OK")
      self.end_headers()
      return

    # Validate GL token

    gitlab_token = self.headers.get(GL_HEADER_TOKEN)
    if not self.config['gitlab'].get('secret-token') or self.config['gitlab'].get('secret-token') != gitlab_token:
      logging.error("Not authorized, Gitlab_Token not authorized")
      self.send_response(401, "Gitlab Token not authorized")
      self.end_headers()
      return

    # Get the project from the json
    try:
      project = json_params['project']
    except KeyError:
      self.send_response(400, "Malformed JSON")
      logging.error("No project provided by the JSON payload")
      self.end_headers()
      return
    logging.debug("Returning 200 OK")
    self.send_response(200, "OK")
    self.end_headers()
    executor.submit(self.process_commits_diff(project, commits))

  def already_scanned(self, project, commit):
    scanned = False
    comments = self.api.get_commit_comments(project, commit) 
    if comments:
      for comment in comments:
        if re.search("^%s.*" % (re.escape(SCAN_MARKER)), comment['note']):
          scanned = True
          break
    return scanned

  def commit_in_default_branch(self, project, commit):
    isIn = False
    for ref in self.api.get_commit_refs(project, commit):
      if ref['type'] == 'branch' and ref['name'] == project['default_branch']:
        isIn = True
        break;
    return isIn

  def commit_is_merge_from_default_branch(self, project, commit):
    isMergeFromDefault = False
    mergeTitle = "Merge branch '%s' into" % (project['default_branch'])
    if re.search("^%s.*" % (re.escape(mergeTitle)), commit['title']):
      isMergeFromDefault = True
    return isMergeFromDefault 

  def process_commits_diff(self, project, commits):
    logging.debug("Processing commits")
    # For each commit in push
    for commit in commits:
      files = {}

      # Check if this commit is already in the default_branch (e.g. main or master)
      if self.commit_in_default_branch(project, commit):
        continue

      # Check if this commit is a merge from the default_branch 
      if self.commit_is_merge_from_default_branch(project, commit):
        continue

      # Check if this commit already has a SCANOSS comment so we don't process it again
      if self.comment_once and self.already_scanned(project, commit):
        continue

      # Get the contents of files in the commit
      for filename in self.api.get_files_in_commit_diff(project, commit):

        contents = self.api.get_file_contents(project, commit, filename)
        if contents:
          files[filename] = contents

      # Send diff to scanner and obtain results
      asset_json = self.api.get_assets_json_file(project, commit, self.sbom_file)
      scan_result = self.scanner.scan_files(files, asset_json)
 
      if scan_result:
        comment = self.scanner.format_scan_results(scan_result)
        
        if comment:
          if self.fix_file_url:
            comment.update({'comment':
              re.sub(re.escape(self.scanoss_url), self.site_url, comment['comment'])})
          if self.comment_always or not comment['validation']:
            status = STATUS_MARKER % ('true' if comment['validation'] else 'false', 
                                      json.dumps(scan_result))
            note = {'note': "%s\n\n%s\n\n<!---\n%s\n--->" % 
                       (SCAN_MARKER, comment['comment'], status)}
            self.api.post_commit_comment(project, commit, note)

          # Update build status for commit
          self.api.update_build_status(project, commit, comment['validation'])
          logging.info("Updated comment and build status")

      else:
        logging.info("The server returned no result for scan")
    logging.debug("Finished processing commits")
