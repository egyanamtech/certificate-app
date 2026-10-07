module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  rootDir: "..",
  roots: ["<rootDir>/tests"],
  testMatch: ["<rootDir>/tests/**/*.test.{ts,js}"],
  transform: {
    "^.+\\.[jt]sx?$": [
      "ts-jest",
      {
        tsconfig: {
          target: "es2017",
          module: "commonjs",
          moduleResolution: "node",
          esModuleInterop: true,
          strict: true,
          skipLibCheck: true,
          jsx: "react-jsx",
          allowJs: true,
          isolatedModules: false,
        },
      },
    ],
  },
  verbose: true,
};