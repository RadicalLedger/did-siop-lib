const yargs = require("yargs");
const argv = yargs(process.argv).parseSync();

//Jest doesn't allow node cli arguments.
//So node cli arguments is loaded and set to process.env before jest env is setup.
process.env["TARGET_DID_TEST_DATA"] = argv.target || "default";

module.exports = {
  testEnvironment: "node",
  transform: {
    "^.+\\.[t|j]sx?$": "<rootDir>/node_modules/babel-jest",
  },
  transformIgnorePatterns: [
    "<rootDir>/node_modules/@babel/plugin-transform-modules-commonjs",
  ],
};
