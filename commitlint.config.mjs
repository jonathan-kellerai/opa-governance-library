// commitlint configuration — enforces Conventional Commits.
//
// Used by the local lefthook hook and by .github/workflows/commitlint.yml.
// The file is an ES module (.mjs) because wagoid/commitlint-github-action
// loads its config that way.
export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      ['feat', 'fix', 'docs', 'chore', 'refactor', 'test', 'ci', 'build', 'perf', 'revert'],
    ],
    'subject-max-length': [2, 'always', 50],
  },
};
