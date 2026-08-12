defmodule RiotTakeHome.ConfigurationTest do
  # async: false on purpose. Every test here rewrites a global application
  # variable to reproduce a different deployment, so running them beside the
  # async suites would pull configuration out from under tests that assume the
  # defaults.
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias RiotTakeHome.Cipher
  alias RiotTakeHome.Payload
  alias RiotTakeHome.Router

  @opts Router.init([])

  defp post_json(path, body) do
    :post
    |> conn(path, body)
    |> put_req_header("content-type", "application/json")
    |> Router.call(@opts)
  end

  defp json_body(conn), do: JSON.decode!(conn.resp_body)

  # Swaps one application variable for the duration of a single test.
  defp swap(key, value) do
    previous = Application.fetch_env!(:riot_take_home, key)
    Application.put_env(:riot_take_home, key, value)
    on_exit(fn -> Application.put_env(:riot_take_home, key, previous) end)
  end

  # The assignment's central requirement: swapping the algorithm must not touch
  # anything else. These tests drive the HTTP endpoints, not the modules, so
  # what they prove is that one line of configuration is genuinely enough.
  describe "swapping the cipher" do
    test "one config line moves /encrypt to AES-256-GCM, and /decrypt follows" do
      assert Cipher.active() == RiotTakeHome.Cipher.Base64
      swap(:cipher, RiotTakeHome.Cipher.AesGcm)

      body = ~s({"age":30,"name":"John Doe"})
      encrypted = post_json("/encrypt", body) |> json_body()

      assert String.starts_with?(encrypted["age"], "enc:aesgcm:")
      refute String.starts_with?(encrypted["age"], "enc:b64:")

      decrypted = post_json("/decrypt", JSON.encode!(encrypted)) |> json_body()
      assert decrypted == JSON.decode!(body)
      assert decrypted["age"] === 30
    end

    test "values written by the previous cipher still decrypt after the swap" do
      # The id travels inside the marker, so a body written before the swap is
      # still readable after it. This is what the marker format buys, and it is
      # the reason no migration step exists.
      legacy = post_json("/encrypt", ~s({"age":30})) |> json_body()
      assert legacy["age"] == "enc:b64:MzA"

      swap(:cipher, RiotTakeHome.Cipher.AesGcm)

      assert post_json("/decrypt", JSON.encode!(legacy)) |> json_body() == %{"age" => 30}
    end
  end

  describe "swapping the signer" do
    test "one config line moves /sign to HMAC-SHA512, and /verify follows" do
      data = ~s({"message":"Hello World","timestamp":1616161616})
      sha256 = post_json("/sign", data) |> json_body() |> Map.fetch!("signature")

      swap(:signer, RiotTakeHome.Signer.HmacSha512)
      sha512 = post_json("/sign", data) |> json_body() |> Map.fetch!("signature")

      refute sha512 == sha256
      assert byte_size(Base.url_decode64!(sha512, padding: false)) == 64

      assert post_json("/verify", ~s({"signature":"#{sha512}","data":#{data}})).status == 204
      # the signature written by the other signer is no longer accepted
      assert post_json("/verify", ~s({"signature":"#{sha256}","data":#{data}})).status == 400
    end
  end

  describe "an encryption key that is absent" do
    setup do
      previous = Application.fetch_env!(:riot_take_home, :encryption_key)
      Application.delete_env(:riot_take_home, :encryption_key)
      on_exit(fn -> Application.put_env(:riot_take_home, :encryption_key, previous) end)

      # 28+ decoded bytes, so the value survives the nonce/tag split and reaches
      # the key lookup, which is where the failure used to be raised.
      %{marker: "enc:aesgcm:" <> Base.url_encode64(:binary.copy("A", 40), padding: false)}
    end

    test "decrypt_payload/1 leaves an aesgcm marker alone when no key is configured", %{
      marker: marker
    } do
      payload = %{"x" => marker}

      assert Payload.decrypt_payload(payload) == payload
    end

    test "POST /decrypt answers 200, not 500, when a marker names a cipher it cannot key", %{
      marker: marker
    } do
      conn = post_json("/decrypt", JSON.encode!(%{"x" => marker}))

      assert conn.status == 200
      assert json_body(conn) == %{"x" => marker}
    end
  end
end
