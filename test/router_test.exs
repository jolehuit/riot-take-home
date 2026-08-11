defmodule RiotTakeHome.RouterTest do
  use ExUnit.Case, async: true

  # `use Plug.Test` is deprecated since Plug 1.20: import the two modules.
  import Plug.Conn
  import Plug.Test

  alias RiotTakeHome.Router

  @opts Router.init([])

  defp post_json(path, body) do
    :post
    |> conn(path, body)
    |> put_req_header("content-type", "application/json")
    |> Router.call(@opts)
  end

  defp json_body(conn), do: JSON.decode!(conn.resp_body)

  defp signature_for(json), do: post_json("/sign", json) |> json_body() |> Map.fetch!("signature")

  @example ~s({"name":"John Doe","age":30,"contact":{"email":"john@example.com","phone":"123-456-7890"}})

  describe "POST /encrypt" do
    test "200 with a marker per depth-1 property" do
      conn = post_json("/encrypt", @example)

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]

      # Hand-computed expected markers (python base64), see payload_test.exs.
      assert json_body(conn) == %{
               "age" => "enc:b64:MzA",
               "name" => "enc:b64:IkpvaG4gRG9lIg",
               "contact" =>
                 "enc:b64:eyJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20iLCJwaG9uZSI6IjEyMy00NTYtNzg5MCJ9"
             }
    end

    test "an object whose root has a literal \"_json\" key is handled correctly" do
      conn = post_json("/encrypt", ~s({"_json":1}))

      assert conn.status == 200
      # base64url of "1" is "MQ"
      assert json_body(conn) == %{"_json" => "enc:b64:MQ"}
    end
  end

  describe "POST /decrypt" do
    test "200, restores types, leaves plaintext fields untouched" do
      encrypted = post_json("/encrypt", @example) |> json_body()
      body = encrypted |> Map.put("birth_date", "1998-11-19") |> JSON.encode!()

      conn = post_json("/decrypt", body)

      assert conn.status == 200
      decrypted = json_body(conn)

      assert decrypted == %{
               "name" => "John Doe",
               "age" => 30,
               "contact" => %{"email" => "john@example.com", "phone" => "123-456-7890"},
               "birth_date" => "1998-11-19"
             }

      assert decrypted["age"] === 30
    end

    test "the false-positive table passes through HTTP unchanged" do
      body =
        ~s({"a":"Riot","b":"MzA=","c":"SGVsbG8=","d":"test","e":"abcd",) <>
          ~s("f":"1998-11-19","g":"John Doe","h":"MDEyOk9yZ2FuaXphdGlvbjYxNDMwNzY2"})

      conn = post_json("/decrypt", body)

      assert conn.status == 200
      assert json_body(conn) == JSON.decode!(body)
    end
  end

  describe "POST /sign" do
    test "200 and the response is exactly {\"signature\": ...}" do
      conn = post_json("/sign", ~s({"message":"Hello World","timestamp":1616161616}))

      assert conn.status == 200
      body = json_body(conn)

      # the literal shape of the assignment example: one key, nothing else
      assert Map.keys(body) == ["signature"]

      # independently computed value, see signature_test.exs
      assert body == %{"signature" => "yO5LzRq16-mJqoLkIzD2zLF995Qj7Exkujn8vClrNvc"}
    end

    test "key order does not change the signature" do
      a = post_json("/sign", ~s({"message":"Hello World","timestamp":1616161616}))
      b = post_json("/sign", ~s({"timestamp":1616161616,"message":"Hello World"}))

      assert a.status == 200
      assert json_body(a) == json_body(b)
    end
  end

  describe "POST /verify" do
    test "204 without a body on a valid signature" do
      data = ~s({"message":"Hello World","timestamp":1616161616})
      signature = signature_for(data)

      conn = post_json("/verify", ~s({"signature":"#{signature}","data":#{data}}))

      assert conn.status == 204
      assert conn.resp_body == ""
    end

    test "204 when the data keys are permuted (symmetry with /sign)" do
      signature = signature_for(~s({"message":"Hello World","timestamp":1616161616}))
      permuted = ~s({"timestamp":1616161616,"message":"Hello World"})

      conn = post_json("/verify", ~s({"signature":"#{signature}","data":#{permuted}}))

      assert conn.status == 204
    end

    test "400 on tampered data" do
      signature = signature_for(~s({"message":"Hello World","timestamp":1616161616}))
      tampered = ~s({"message":"Hello World","timestamp":1616161617})

      conn = post_json("/verify", ~s({"signature":"#{signature}","data":#{tampered}}))

      assert conn.status == 400
    end

    test "400 (not 500) on a signature of the wrong size" do
      # :crypto.hash_equals/2 raises when byte sizes differ: this request
      # must hit the size guard, not the exception
      conn = post_json("/verify", ~s({"signature":"abc","data":{"a":1}}))

      assert conn.status == 400
    end

    test "400 without data" do
      conn = post_json("/verify", ~s({"signature":"abc"}))
      assert conn.status == 400
    end

    test "400 without signature" do
      conn = post_json("/verify", ~s({"data":{"a":1}}))
      assert conn.status == 400
    end

    test "400 on a non-string signature" do
      conn = post_json("/verify", ~s({"signature":42,"data":{"a":1}}))
      assert conn.status == 400
    end

    test "400 on non-object data" do
      conn = post_json("/verify", ~s({"signature":"abc","data":[1,2]}))
      assert conn.status == 400
    end
  end

  describe "malformed input" do
    test "400 on malformed JSON" do
      conn = post_json("/encrypt", ~s({"broken":))

      assert conn.status == 400
      assert json_body(conn) == %{"error" => "malformed JSON body"}
    end

    test "400 on an empty body" do
      conn = post_json("/encrypt", "")

      assert conn.status == 400
      assert json_body(conn) == %{"error" => "request body must be a JSON object"}
    end

    test "400 on a non-object root, for every endpoint" do
      for path <- ["/encrypt", "/decrypt", "/sign", "/verify"],
          body <- [~s([1,2,3]), ~s("a string"), "30", "null", "true"] do
        conn = post_json(path, body)
        assert conn.status == 400, "#{path} with root #{body} must be 400, got #{conn.status}"
      end
    end

    test "413 on a body above the explicit 1 MiB limit" do
      big = ~s({"big":") <> String.duplicate("a", 1_100_000) <> ~s("})
      conn = post_json("/encrypt", big)

      assert conn.status == 413
      assert json_body(conn) == %{"error" => "request body exceeds the limit of 1048576 bytes"}
    end
  end

  describe "content-type" do
    test "400 when the header is absent (the body is left unparsed)" do
      conn = :post |> conn("/encrypt", ~s({"a":1})) |> Router.call(@opts)

      assert conn.status == 400
      assert json_body(conn) == %{"error" => "request body must be a JSON object"}
    end

    test "415 on a wrong content-type" do
      conn =
        :post
        |> conn("/sign", ~s({"a":1}))
        |> put_req_header("content-type", "text/plain")
        |> Router.call(@opts)

      assert conn.status == 415
      assert json_body(conn) == %{"error" => "content-type must be application/json"}
    end

    test "media-type parameters are tolerated" do
      conn =
        :post
        |> conn("/sign", ~s({"a":1}))
        |> put_req_header("content-type", "application/json; charset=utf-8")
        |> Router.call(@opts)

      assert conn.status == 200
    end
  end

  describe "routing" do
    test "404 on an unknown route" do
      conn = post_json("/nope", ~s({"a":1}))

      assert conn.status == 404
      assert json_body(conn) == %{"error" => "not found"}
    end

    test "404 on a known path with the wrong method" do
      conn = :get |> conn("/encrypt") |> Router.call(@opts)

      assert conn.status == 404
    end

    test "404 on an unknown route with a malformed body and no content-type" do
      # No content-type means the body is never parsed, so an unknown route
      # falls through to the catch-all 404 rather than a parse error.
      conn = :post |> conn("/unknown", ~s({"broken":)) |> Router.call(@opts)

      assert conn.status == 404
    end
  end
end
