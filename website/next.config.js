/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  basePath: process.env.NODE_ENV === 'production' ? '/low-level-km' : '',
  assetPrefix: process.env.NODE_ENV === 'production' ? '/low-level-km/' : '',
}

module.exports = nextConfig
