import eslint from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

const typedFiles = [
  "src/**/*.ts",
  "worker/**/*.ts",
  "vite.config.ts",
  "vitest.config.ts"
];

export default tseslint.config(
  {
    ignores: ["dist/**", "node_modules/**", ".wrangler/**"]
  },
  {
    files: ["eslint.config.js", "scripts/**/*.mjs"],
    ...eslint.configs.recommended,
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: globals.node
    }
  },
  {
    files: typedFiles,
    extends: [
      eslint.configs.recommended,
      ...tseslint.configs.strict,
      ...tseslint.configs.strictTypeCheckedOnly
    ],
    languageOptions: {
      parserOptions: {
        project: ["./tsconfig.build.json", "./tsconfig.worker.json", "./tsconfig.test.json"],
        tsconfigRootDir: import.meta.dirname
      }
    },
    linterOptions: {
      reportUnusedDisableDirectives: "error"
    },
    rules: {
      "no-undef": "off",
      "@typescript-eslint/consistent-type-imports": [
        "error",
        {
          "fixStyle": "inline-type-imports",
          "prefer": "type-imports"
        }
      ],
      "@typescript-eslint/no-import-type-side-effects": "error",
      "@typescript-eslint/no-confusing-void-expression": [
        "error",
        {
          "ignoreArrowShorthand": true,
          "ignoreVoidOperator": true,
          "ignoreVoidReturningFunctions": true
        }
      ],
      "@typescript-eslint/no-misused-promises": [
        "error",
        {
          "checksVoidReturn": {
            "arguments": false
          }
        }
      ],
      "@typescript-eslint/require-await": "off",
      "@typescript-eslint/restrict-plus-operands": [
        "error",
        {
          "allowAny": true
        }
      ],
      "@typescript-eslint/restrict-template-expressions": [
        "error",
        {
          "allowNumber": true
        }
      ],
      "@typescript-eslint/switch-exhaustiveness-check": "error",
      "curly": ["error", "all"],
      "eqeqeq": ["error", "always"]
    }
  },
  {
    files: ["src/**/*.ts"],
    languageOptions: {
      globals: globals.browser
    }
  },
  {
    files: ["src/api/client.ts"],
    rules: {
      "@typescript-eslint/no-unsafe-assignment": "off"
    }
  },
  {
    files: ["src/domain/validation.ts"],
    rules: {
      "no-control-regex": "off"
    }
  },
  {
    files: ["src/ui/dom.ts"],
    rules: {
      "@typescript-eslint/no-deprecated": "off",
      "@typescript-eslint/no-unnecessary-condition": "off"
    }
  },
  {
    files: ["worker/**/*.ts"],
    languageOptions: {
      globals: globals.worker
    },
    rules: {
      "@typescript-eslint/no-unnecessary-condition": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off"
    }
  },
  {
    files: ["**/*.test.ts", "vite.config.ts", "vitest.config.ts"],
    languageOptions: {
      globals: globals.node
    },
    rules: {
      "@typescript-eslint/no-base-to-string": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/restrict-template-expressions": [
        "error",
        {
          "allowAny": true,
          "allowNumber": true
        }
      ]
    }
  }
);
