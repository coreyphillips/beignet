'use strict';

/* eslint-disable @typescript-eslint/no-var-requires */
const js = require('@eslint/js');
const tsPlugin = require('@typescript-eslint/eslint-plugin');
const prettierRecommended = require('eslint-plugin-prettier/recommended');

module.exports = [
	{
		ignores: [
			'**/dist/',
			'**/api-docs/',
			// `npm run lint` never reached these under ESLint 8 (its --ext list
			// had no .cjs or .mjs), and they have findings under the rules here.
			// Linting them is a change of its own.
			'tests/**/*.cjs',
			'**/*.mjs'
		]
	},
	{
		// ESLint 8 did not report unused disable directives by default.
		linterOptions: { reportUnusedDisableDirectives: 'off' }
	},
	js.configs.recommended,
	...tsPlugin.configs['flat/recommended'],
	prettierRecommended,
	{
		rules: {
			semi: ['error'],
			'no-shadow': 'off',
			'@typescript-eslint/no-shadow': 'error',
			'@typescript-eslint/no-unused-vars': [
				'error',
				{
					argsIgnorePattern: '^_',
					varsIgnorePattern: '^_',
					caughtErrors: 'none'
				}
			],
			'no-console': 0,
			'no-empty': ['error', { allowEmptyCatch: true }],
			'no-buffer-constructor': 0,
			'no-case-declarations': 0,
			'no-useless-escape': 0,
			indent: 'off',
			'object-curly-spacing': ['error', 'always', { objectsInObjects: true }],
			'no-undef': 0,
			'require-atomic-updates': 0,
			'no-async-promise-executor': 0,
			'brace-style': [2, '1tbs', { allowSingleLine: true }],
			'@typescript-eslint/explicit-function-return-type': 'warn',
			'@typescript-eslint/ban-ts-comment': 'off',
			'@typescript-eslint/no-non-null-assertion': 'off',
			'@typescript-eslint/no-explicit-any': 'warn',
			'@typescript-eslint/no-require-imports': 'off',
			'@typescript-eslint/no-var-requires': 'error',
			'@typescript-eslint/no-duplicate-enum-values': 'off',
			'@typescript-eslint/no-unused-expressions': [
				'error',
				{ allowTernary: true }
			],
			'@typescript-eslint/adjacent-overload-signatures': 'error',
			'@typescript-eslint/no-empty-function': 'error',
			'@typescript-eslint/no-empty-interface': 'error',
			'@typescript-eslint/no-inferrable-types': 'error',
			'@typescript-eslint/no-loss-of-precision': 'error',
			'no-class-assign': 'error',
			'no-with': 'error'
		}
	},
	{
		// eslint:recommended as ESLint 8 had it. ESLint 9 and 10 added the
		// rules turned off here, dropped no-inner-declarations, and changed
		// the defaults of the last two. Taking any of that is its own change.
		rules: {
			'no-constant-binary-expression': 'off',
			'no-empty-static-block': 'off',
			'no-unassigned-vars': 'off',
			'no-unused-private-class-members': 'off',
			'no-useless-assignment': 'off',
			'preserve-caught-error': 'off',
			'no-inner-declarations': [
				'error',
				'functions',
				{ blockScopedFunctions: 'disallow' }
			],
			'no-constant-condition': ['error', { checkLoops: 'all' }],
			'no-shadow-restricted-names': ['error', { reportGlobalThis: false }]
		}
	},
	{
		files: ['**/*.ts', '**/*.tsx'],
		rules: {
			semi: 'off'
		}
	},
	{
		files: ['src/lightning/**/*.ts', 'src/cli/**/*.ts'],
		rules: {
			'@typescript-eslint/no-var-requires': 'off'
		}
	},
	{
		files: ['src/**/*.ts'],
		rules: {
			'@typescript-eslint/consistent-type-imports': [
				'error',
				{ disallowTypeAnnotations: false }
			]
		}
	},
	{
		files: ['tests/**/*.ts'],
		rules: {
			'@typescript-eslint/no-var-requires': 'off',
			'@typescript-eslint/no-empty-function': 'off',
			'@typescript-eslint/no-empty-object-type': 'off',
			'@typescript-eslint/no-unsafe-function-type': 'off',
			'@typescript-eslint/no-wrapper-object-types': 'off',
			'@typescript-eslint/no-unused-expressions': 'off'
		}
	},
	{
		files: ['**/*.ts'],
		languageOptions: {
			parserOptions: {
				project: ['./tsconfig.test.json'],
				tsconfigRootDir: __dirname
			}
		},
		rules: {
			'@typescript-eslint/no-floating-promises': 'error',
			'@typescript-eslint/no-misused-promises': 'error'
		}
	},
	{
		files: ['scripts/regtest-live/*-qualification/**/*.cjs'],
		rules: {
			'@typescript-eslint/no-var-requires': 'off',
			'@typescript-eslint/explicit-function-return-type': 'off'
		}
	}
];
