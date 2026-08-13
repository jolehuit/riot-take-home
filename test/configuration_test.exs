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

      # Nothing marks the algorithm on the wire, but the wire layout betrays
      # it: an AES value decodes to nonce(12) || tag(16) || ciphertext, where
      # plain base64 of "30" would decode to 2 bytes.
      assert byte_size(Base.decode64!(encrypted["age"])) == 12 + 16 + 2

      decrypted = post_json("/decrypt", JSON.encode!(encrypted)) |> json_body()
      assert decrypted == JSON.decode!(body)
      assert decrypted["age"] === 30
    end

    test "values written by the previous cipher stop decrypting after the swap" do
      # No algorithm id travels with a value, so /decrypt can only ask the
      # active cipher. After the swap the base64 value is handed to AES-GCM,
      # whose tag verification rejects it as not its own, and it passes
      # through unchanged: swapping the cipher is a clean cut, not a
      # migration, and reading old values back would need one.
      legacy = post_json("/encrypt", ~s({"age":30})) |> json_body()
      assert legacy == %{"age" => "MzA="}

      swap(:cipher, RiotTakeHome.Cipher.AesGcm)

      assert post_json("/decrypt", JSON.encode!(legacy)) |> json_body() == legacy
    end
  end

  describe "swapping the signer" do
    test "one config line moves /sign to HMAC-SHA512, and /verify follows" do
      data = ~s({"message":"Hello World","timestamp":1616161616})
      sha256 = post_json("/sign", data) |> json_body() |> Map.fetch!("signature")

      swap(:signer, RiotTakeHome.Signer.HmacSha512)
      sha512 = post_json("/sign", data) |> json_body() |> Map.fetch!("signature")

      refute sha512 == sha256
      assert byte_size(Base.decode16!(sha512, case: :lower)) == 64

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
      %{blob: Base.encode64(:binary.copy("A", 40))}
    end

    test "decrypt_payload/1 leaves an AES-shaped value alone when no key is configured", %{
      blob: blob
    } do
      swap(:cipher, RiotTakeHome.Cipher.AesGcm)
      payload = %{"x" => blob}

      assert Payload.decrypt_payload(payload) == payload
    end

    test "POST /decrypt answers 200, not 500, when the active cipher cannot be keyed", %{
      blob: blob
    } do
      swap(:cipher, RiotTakeHome.Cipher.AesGcm)
      conn = post_json("/decrypt", JSON.encode!(%{"x" => blob}))

      assert conn.status == 200
      assert json_body(conn) == %{"x" => blob}
    end
  end
end
