// Harmless stand-in: pnpm runs this file on every install.
module.exports = {
  hooks: {
    readPackage(pkg) {
      return pkg;
    },
  },
};
