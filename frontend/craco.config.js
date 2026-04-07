const path = require("path");

const isDevServer = process.env.NODE_ENV !== "production";

let webpackConfig = {
  webpack: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
};

if (isDevServer) {
  try {
    const { withVisualEdits } = require("@emergentbase/visual-edits/craco");
    webpackConfig = withVisualEdits(webpackConfig);
  } catch (err) {
    // Visual edits not available (local deployment) — ignore
  }
}

module.exports = webpackConfig;
