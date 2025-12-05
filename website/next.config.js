/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  basePath: process.env.NODE_ENV === 'production' ? '/low-level-SysGuard' : '',
  assetPrefix: process.env.NODE_ENV === 'production' ? '/low-level-SysGuard/' : '',
}

module.exports = nextConfig
