module.exports = {
  env: {
    browser: true,
    es2021: true,
  },
  extends: ['eslint:recommended'],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  globals: {
    _db: 'readonly',
  },
  rules: {
    'no-unused-vars': ['warn', { args: 'none', varsIgnorePattern: '^_' }],
    'no-empty': 'off',
  },
};
