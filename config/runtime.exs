import Config

# The signing secret only ever comes from the environment: no default value
# lives in the repository. Outside of tests the application refuses to boot
# without it, so a misconfigured deployment fails at startup, not at the
# first signed request.
if config_env() != :test do
  case System.fetch_env("SIGNING_SECRET") do
    {:ok, secret} when secret != "" ->
      config :riot_take_home, signing_secret: secret

    _ ->
      raise """
      environment variable SIGNING_SECRET is missing or empty.
      Set it before starting the server, e.g.:

          SIGNING_SECRET=change-me mix run --no-halt
      """
  end
end

# Optional: only the AES-256-GCM cipher needs it, and base64 is the default,
# so an absent key is a normal start. A present key must be exactly 32 bytes,
# base64-encoded; anything else is a misconfiguration and refuses the boot,
# the same way a missing SIGNING_SECRET does.
if config_env() != :test do
  case System.fetch_env("ENCRYPTION_KEY") do
    {:ok, encoded} ->
      case Base.decode64(encoded) do
        {:ok, key} when byte_size(key) == 32 ->
          config :riot_take_home, encryption_key: key

        _ ->
          raise """
          environment variable ENCRYPTION_KEY must be 32 bytes, base64-encoded.
          Generate one with:

              openssl rand -base64 32
          """
      end

    :error ->
      # Absent is a normal start under base64, but not under a cipher that
      # needs a key: that combination would answer 500 on the first /encrypt,
      # so it fails here instead, where the message can say what is missing.
      if Application.compile_env(:riot_take_home, :cipher) == RiotTakeHome.Cipher.AesGcm do
        raise """
        the active cipher is AES-256-GCM, which needs ENCRYPTION_KEY.
        Set it, or leave the default base64 cipher in config/config.exs:

            ENCRYPTION_KEY=$(openssl rand -base64 32) mix run --no-halt
        """
      end
  end
end

if port = System.get_env("PORT") do
  case Integer.parse(port) do
    {number, ""} when number > 0 ->
      config :riot_take_home, port: number

    _ ->
      raise "environment variable PORT must be a positive integer, got: #{inspect(port)}"
  end
end
