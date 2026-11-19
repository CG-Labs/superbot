// Extends app.json. SUPERBOT_WEB_BASE_URL (e.g. "/app") sets the path a server-hosted web
// build lives under. Leave it unset for native, Electron, and dev builds.
module.exports = ({ config }) => {
  const baseUrl = process.env.SUPERBOT_WEB_BASE_URL;
  if (!baseUrl) return config;
  if (!/^(\/[A-Za-z0-9._~-]+)+$/.test(baseUrl)) {
    throw new Error(`SUPERBOT_WEB_BASE_URL must look like "/app" (no trailing slash), not "${baseUrl}"`);
  }
  return { ...config, experiments: { ...config.experiments, baseUrl } };
};
