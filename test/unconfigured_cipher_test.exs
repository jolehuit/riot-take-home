defmodule RiotTakeHome.UnconfiguredCipherTest do
  # async: false on purpose. These tests remove a global application variable
  # to reproduce the real runtime configuration, where base64 is the active
  # cipher and ENCRYPTION_KEY is unset. Run concurrently with the other suites
  # they would pull that key out from under any test that encrypts with AES.
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias RiotTakeHome.Payload
  alias RiotTakeHome.Router

  @opts Router.init([])

  setup do
    secret = Application.fetch_env!(:riot_take_home, :encryption_secret)
    Application.delete_env(:riot_take_home, :encryption_secret)
    on_exit(fn -> Application.put_env(:riot_take_home, :encryption_secret, secret) end)
    # 28+ decoded bytes, so the value survives the nonce/tag split and reaches
    # the key lookup, which is where the failure used to be raised.
    %{marker: "enc:aesgcm:" <> Base.url_encode64(:binary.copy("A", 40), padding: false)}
  end

  describe "decrypt_payload/1" do
    test "leaves an aesgcm marker alone when no encryption key is configured", %{marker: marker} do
      payload = %{"x" => marker}

      assert Payload.decrypt_payload(payload) == payload
    end
  end

  describe "POST /decrypt" do
    test "answers 200, not 500, when a marker names a cipher the server cannot key", %{
      marker: marker
    } do
      body = JSON.encode!(%{"x" => marker})

      conn =
        :post
        |> conn("/decrypt", body)
        |> put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 200
      assert JSON.decode!(conn.resp_body) == %{"x" => marker}
    end
  end
end
