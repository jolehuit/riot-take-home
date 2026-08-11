import Config

config :riot_take_home,
  signing_secret: "test-only-secret",
  encryption_secret: "test-only-encryption-secret",
  # Ephemeral port: the test suite exercises the plug directly and must not
  # collide with a dev server that may already hold 4000.
  port: 0
