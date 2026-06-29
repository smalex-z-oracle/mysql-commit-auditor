#!/usr/bin/env node

'use strict';

const fs = require('fs');

const MARKER = 'mysql-code-submission-guard:v1';
const ALLOW_MARKER = '<!-- code-guard: allow -->';
const WARNING = [
  `<!-- ${MARKER} -->`,
  '',
  'This message appears to contain a proposed code contribution. Please submit code contributions through a GitHub Pull Request so the Oracle Contributor Agreement (OCA) verification process can be completed. Minimal reproduction snippets, SQL examples, configuration excerpts, and diagnostic logs are welcome here.',
].join('\n');

function getPayload() {
  return JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
}

function getTarget(eventName, payload) {
  const repo = payload.repository && {
    owner: payload.repository.owner.login,
    name: payload.repository.name,
  };

  if (eventName === 'issues') {
    return {
      type: 'issue',
      repo,
      body: payload.issue?.body || '',
      issueNumber: payload.issue?.number,
      actor: payload.issue?.user?.login,
      actorType: payload.issue?.user?.type,
    };
  }

  if (eventName === 'issue_comment') {
    if (payload.issue?.pull_request) return { skip: 'pull_request_comment' };
    return {
      type: 'issue_comment',
      repo,
      body: payload.comment?.body || '',
      issueNumber: payload.issue?.number,
      actor: payload.comment?.user?.login,
      actorType: payload.comment?.user?.type,
    };
  }

  if (eventName === 'discussion') {
    return {
      type: 'discussion',
      repo,
      body: payload.discussion?.body || '',
      discussionId: payload.discussion?.node_id,
      actor: payload.discussion?.user?.login,
      actorType: payload.discussion?.user?.type,
    };
  }

  if (eventName === 'discussion_comment') {
    return {
      type: 'discussion_comment',
      repo,
      body: payload.comment?.body || '',
      discussionId: payload.discussion?.node_id,
      replyToId: payload.comment?.node_id,
      actor: payload.comment?.user?.login,
      actorType: payload.comment?.user?.type,
    };
  }

  return { skip: `unsupported_event:${eventName}` };
}

function shouldSkip(target) {
  if (target.skip) return target.skip;
  if (!target.repo) return 'missing_repo';
  if (!target.body.trim()) return 'empty_body';
  if (target.body.includes(MARKER)) return 'own_warning';
  if (target.body.includes(ALLOW_MARKER)) return 'allow_marker';
  if (target.actorType === 'Bot' || /\[bot\]$/i.test(target.actor || '')) return 'bot_actor';
  return null;
}

function codeBlocks(markdown) {
  const blocks = [];
  const fence = /(^|\n)(`{3,}|~{3,})([^\r\n`]*)\r?\n([\s\S]*?)(?:\r?\n\2)(?=\r?\n|$)/g;
  let match;

  while ((match = fence.exec(markdown)) !== null) {
    blocks.push({
      language: (match[3] || '').trim().split(/\s+/)[0].toLowerCase(),
      text: match[4],
      lines: match[4].split(/\r?\n/).filter((line) => line.trim()).length,
    });
  }

  return blocks;
}

function looksLikeSource(text) {
  return (
    /^\s*#include\s+[<"][^>"]+[>"]/m.test(text) ||
    /^\s*(class|struct|enum)\s+[A-Za-z_][A-Za-z0-9_:]*\b/m.test(text) ||
    /^\s*(bool|int|void|char|double|float|size_t|std::[A-Za-z_][A-Za-z0-9_:<>]*)\s+[A-Za-z_][A-Za-z0-9_:]*\s*\([^;{}]*\)\s*\{/m.test(
      text,
    )
  );
}

function looksDiagnostic(block) {
  const lang = block.language;
  if (['sql', 'mysql', 'ini', 'cnf', 'conf', 'log', 'yaml', 'yml', 'json'].includes(lang)) {
    return !looksLikeSource(block.text);
  }

  return (
    /^mysql>\s+/m.test(block.text) ||
    /^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}/m.test(block.text) ||
    /^\s*(#\d+|at)\s+/m.test(block.text) ||
    /^\s*[A-Za-z0-9_.-]+\s*=\s*.+/m.test(block.text)
  );
}

function classify(markdown) {
  if (/^diff --git\s+/m.test(markdown) || /^@@ -\d+(,\d+)? \+\d+(,\d+)? @@/m.test(markdown)) {
    return { result: 'warn', reason: 'diff' };
  }

  const blocks = codeBlocks(markdown);
  const sourceBlocks = blocks.filter((block) => !looksDiagnostic(block) && looksLikeSource(block.text));
  const sourceLines = sourceBlocks.reduce((total, block) => total + block.lines, 0);
  const saysFix = /\b(here(?:'s| is) my fix|apply this patch|patch below|proposed patch|this code fixes|please merge)\b/i.test(
    markdown,
  );

  if (saysFix && sourceBlocks.length > 0) {
    return { result: 'warn', reason: 'fix_phrase_with_source' };
  }

  if (sourceLines >= 80) {
    return { result: 'warn', reason: 'large_source_block' };
  }

  return { result: 'allow', reason: 'no_obvious_submission' };
}

async function githubRest(path, options = {}) {
  const response = await fetch(`https://api.github.com${path}`, {
    ...options,
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      'Content-Type': 'application/json',
      'User-Agent': 'mysql-code-submission-guard',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(options.headers || {}),
    },
  });

  if (!response.ok) {
    throw new Error(`GitHub REST ${response.status}: ${await response.text()}`);
  }

  return response.status === 204 ? null : response.json();
}

async function githubGraphql(query, variables) {
  const response = await fetch('https://api.github.com/graphql', {
    method: 'POST',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      'Content-Type': 'application/json',
      'User-Agent': 'mysql-code-submission-guard',
    },
    body: JSON.stringify({ query, variables }),
  });
  const data = await response.json();

  if (!response.ok || data.errors) {
    throw new Error(`GitHub GraphQL error: ${JSON.stringify(data.errors || data)}`);
  }

  return data.data;
}

async function issueAlreadyWarned(target) {
  const comments = await githubRest(
    `/repos/${target.repo.owner}/${target.repo.name}/issues/${target.issueNumber}/comments?per_page=100`,
  );
  return comments.some((comment) => comment.body?.includes(MARKER));
}

async function warnIssue(target) {
  if (await issueAlreadyWarned(target)) return 'duplicate_suppressed';

  await githubRest(`/repos/${target.repo.owner}/${target.repo.name}/issues/${target.issueNumber}/comments`, {
    method: 'POST',
    body: JSON.stringify({ body: WARNING }),
  });
  return 'warning_posted';
}

async function discussionAlreadyWarned(target) {
  const data = await githubGraphql(
    `query ExistingGuardWarning($id: ID!) {
      node(id: $id) {
        ... on Discussion {
          comments(first: 100) {
            nodes {
              body
              replies(first: 100) {
                nodes { body }
              }
            }
          }
        }
      }
    }`,
    { id: target.discussionId },
  );

  const comments = data.node?.comments?.nodes || [];
  return comments.some(
    (comment) =>
      comment.body?.includes(MARKER) ||
      (comment.replies?.nodes || []).some((reply) => reply.body?.includes(MARKER)),
  );
}

async function warnDiscussion(target) {
  if (await discussionAlreadyWarned(target)) return 'duplicate_suppressed';

  await githubGraphql(
    `mutation AddGuardWarning($discussionId: ID!, $replyToId: ID, $body: String!) {
      addDiscussionComment(input: {discussionId: $discussionId, replyToId: $replyToId, body: $body}) {
        comment { id }
      }
    }`,
    { discussionId: target.discussionId, replyToId: target.replyToId || null, body: WARNING },
  );
  return 'warning_posted';
}

async function postWarning(target) {
  if (process.env.CODE_SUBMISSION_GUARD_DRY_RUN === 'true') return 'dry_run';
  if (target.type === 'issue' || target.type === 'issue_comment') return warnIssue(target);
  if (target.type === 'discussion' || target.type === 'discussion_comment') return warnDiscussion(target);
  return 'unsupported_target';
}

async function main() {
  const eventName = process.env.GITHUB_EVENT_NAME;
  const target = getTarget(eventName, getPayload());
  const skip = shouldSkip(target);

  if (skip) {
    console.log(JSON.stringify({ eventName, result: 'skip', reason: skip }));
    return;
  }

  const decision = classify(target.body);
  const action = decision.result === 'warn' ? await postWarning(target) : 'none';
  console.log(JSON.stringify({ eventName, target: target.type, ...decision, action }));
}

if (process.argv.includes('--self-test')) {
  const examples = [
    ['sql', '```sql\nSELECT * FROM t;\n```', 'allow'],
    ['diff', '```diff\ndiff --git a/sql/a.cc b/sql/a.cc\n@@ -1 +1 @@\n```', 'warn'],
    ['fix', 'Here is my fix:\n```cpp\nbool f() { return true; }\n```', 'warn'],
  ];

  for (const [name, body, expected] of examples) {
    const actual = classify(body).result;
    console.log(JSON.stringify({ name, expected, actual, ok: actual === expected }));
    if (actual !== expected) process.exitCode = 1;
  }
} else {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
