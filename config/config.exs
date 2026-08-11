import Config

config :riot_take_home,
  port: 4000,
  cipher: RiotTakeHome.Cipher.Base64,
  signer: RiotTakeHome.Signer.HmacSha256

if config_env() == :test do
  import_config "test.exs"
end
