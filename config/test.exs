import Config

config :riot_take_home,
  signing_secret: "test-only-secret",
  # The 32 bytes 0x00..0x1f: the key the external vector in
  # aes_gcm_vector_test.exs was generated under.
  encryption_key: Base.decode64!("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
  # Ephemeral port: the test suite exercises the plug directly and must not
  # collide with a dev server that may already hold 4000.
  port: 0
