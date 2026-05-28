// commitlint configuration — enforces Conventional Commits.
//
// Used by the local lefthook hook and by .github/workflows/commitlint.yml.
// Renamed from commitlint.config.mjs; converted to CommonJS so that the
// standard required filename (commitlint.config.js) is satisfied.
module.exports = {
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
