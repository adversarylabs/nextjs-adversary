module.exports = {
  experimental: {
    serverActions: {
      allowedOrigins: [
        '*',
        '**',
        'app.example.com',
        '*.my-proxy.com',
        '**.my-proxy.com',
        '*.localhost',
      ],
    },
  },
};
