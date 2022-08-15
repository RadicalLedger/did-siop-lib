module.exports = {
  testEnvironment: "node",
  transform: {
    "^.+\\.[t|j]sx?$": "<rootDir>/node_modules/babel-jest",
  },
  transformIgnorePatterns: [
    "<rootDir>/node_modules/@babel/plugin-transform-modules-commonjs",
  ],
};
