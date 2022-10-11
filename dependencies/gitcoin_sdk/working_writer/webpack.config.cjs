const path = require('path');

module.exports = [{
  entry: './src/writer.ts',
  output: {
    // publicPath: '',
    path: path.resolve(__dirname, 'dist'),
    filename: 'writer.bundle.js',
    library: 'PassportWriter',
    libraryExport: 'PassportWriter',
    libraryTarget: 'var',
  },
  resolve: {
    extensions: ['.ts', '.d.ts', '.js', '.json']
  },
  module: {
    rules: [
      {
        test: /\.d\.ts$/,
        loader: 'ignore-loader'
      },
      { 
        test: /.tsx?$/, 
        loader: 'ts-loader', 
        exclude: /node_modules|\.d\.ts$/
      }
    ]
  },
}];
