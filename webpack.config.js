const path = require('path');
const NodePolyfillPlugin = require("node-polyfill-webpack-plugin")
const TerserPlugin = require("terser-webpack-plugin");

module.exports = {
    entry: './src/index.ts',
    mode:"production",
    module: {
      rules: [
        {
          test: /\.tsx?$/,
          use: 'ts-loader',
          exclude: /node_modules/,
        },
      ],
    },
    resolve: {
      extensions: ['.tsx', '.ts', '.js'],
    },  
    output: {
      filename: 'did-siop.min.js',
      path: path.resolve(__dirname, 'dist/browser'),
      library: 'DID_SIOP'
    },
    plugins: [ new NodePolyfillPlugin()],
    optimization: {
      minimize: true,
      minimizer: [new TerserPlugin({})
      ],
    },      
  };