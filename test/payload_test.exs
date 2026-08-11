defmodule RiotTakeHome.PayloadTest do
  use ExUnit.Case, async: true

  alias RiotTakeHome.Cipher.AesGcm
  alias RiotTakeHome.Payload

  # The literal example of the assignment.
  @example %{
    "name" => "John Doe",
    "age" => 30,
    "contact" => %{"email" => "john@example.com", "phone" => "123-456-7890"}
  }

  # The false-positive table.
  # None of these strings is encrypted, so /decrypt must return every one of
  # them strictly unchanged. Each one is a counter-example to the naive
  # detection rule, "if it decodes as base64, it was encrypted":
  @false_positives [
    # decodes as base64 into valid UTF-8 bytes: the naive heuristic
    # destroys the company's own name.
    "Riot",
    # decodes to "30", which is valid JSON: the double heuristic
    # (base64 then JSON) silently turns this string into the number 30.
    "MzA=",
    # decodes to "Hello": valid UTF-8 again, corrupted by the heuristic.
    "SGVsbG8=",
    # 4 characters, valid base64 alphabet, decodes without error.
    "test",
    # same: any 4-letter [a-z] word is valid base64.
    "abcd",
    # the assignment's own plaintext example. Safe from the heuristic only
    # by accident: the dashes are outside the standard base64 alphabet.
    "1998-11-19",
    # the assignment's other plaintext example, safe only thanks to the
    # space. "John" alone would have been corrupted.
    "John Doe",
    # a real GitHub node_id: decodes to "012:Organization61430766".
    # Real-world identifiers are frequently valid base64.
    "MDEyOk9yZ2FuaXphdGlvbjYxNDMwNzY2"
  ]

  # All expected markers in this file were computed by hand (python:
  # urlsafe base64 of the JSON encoding, padding stripped), never with the
  # code under test.
  describe "encrypt_payload/1" do
    test "the assignment example encrypts to the documented markers" do
      assert Payload.encrypt_payload(@example) == %{
               "age" => "enc:b64:MzA",
               "name" => "enc:b64:IkpvaG4gRG9lIg",
               "contact" =>
                 "enc:b64:eyJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20iLCJwaG9uZSI6IjEyMy00NTYtNzg5MCJ9"
             }
    end
  end

  describe "decrypt_payload/1" do
    test "unencrypted strings pass through strictly unchanged" do
      payload =
        Map.new(Enum.with_index(@false_positives), fn {value, i} -> {"key_#{i}", value} end)

      assert Payload.decrypt_payload(payload) == payload
    end

    test "a marker nested at depth 2 comes back unchanged" do
      original = %{"outer" => %{"inner" => "enc:b64:MzA"}}

      # Both operations act at depth 1 only: on decrypt the value of "outer"
      # is an object, not a marked string, so the nested marker is untouched.
      assert Payload.decrypt_payload(original) == original

      # Through a full round trip the nested marker also survives verbatim
      # (it is encrypted as part of the depth-1 object, then restored).
      assert original |> Payload.encrypt_payload() |> Payload.decrypt_payload() == original
    end

    test "malformed or unknown markers come back strictly unchanged" do
      payload = %{
        # well-formed marker, but "aes" is not a registered algorithm id
        "unknown_alg" => "enc:aes:xxxx",
        # known id, invalid base64 payload
        "broken_b64" => "enc:b64:!!!",
        # prefix with no id and no data
        "bare_prefix" => "enc:",
        # known id, empty data: decodes to "" which is not valid JSON
        "empty_data" => "enc:b64:",
        # known id, but padded input: encoding is unpadded, decoding is strict
        "padded_b64" => "enc:b64:MzA="
      }

      assert Payload.decrypt_payload(payload) == payload
    end

    test "an aesgcm marker is left alone when no encryption key is configured" do
      # The runtime default is base64 with no ENCRYPTION_KEY set, so a request
      # can name a cipher the server cannot key. Decryption of untrusted input
      # must never raise: the value is simply not decryptable and passes through.
      secret = Application.fetch_env!(:riot_take_home, :encryption_secret)
      Application.delete_env(:riot_take_home, :encryption_secret)
      on_exit(fn -> Application.put_env(:riot_take_home, :encryption_secret, secret) end)

      # 28+ decoded bytes, so it survives the nonce/tag split and reaches the key
      payload = %{
        "x" => "enc:aesgcm:" <> Base.url_encode64(:binary.copy("A", 40), padding: false)
      }

      assert Payload.decrypt_payload(payload) == payload
    end

    test "b64 and aesgcm markers coexist in one body without migration" do
      # The marker is built by hand here on purpose: this pins the wire format
      # "enc:<alg_id>:<data>", not just the round trip.
      aes_value = "enc:aesgcm:" <> AesGcm.encrypt(JSON.encode!(%{"n" => 1}))
      payload = %{"a" => aes_value, "b" => "enc:b64:MzA"}

      assert Payload.decrypt_payload(payload) == %{"a" => %{"n" => 1}, "b" => 30}
    end
  end

  describe "encrypt_payload/1 then decrypt_payload/1 (round trip)" do
    test "the assignment example round-trips with its original types" do
      decrypted = @example |> Payload.encrypt_payload() |> Payload.decrypt_payload()

      assert decrypted == @example
      # `==` alone would accept 30.0 for 30; pin the types explicitly.
      assert decrypted["age"] === 30
      assert is_integer(decrypted["age"])
      assert is_map(decrypted["contact"])
      assert decrypted["contact"]["phone"] === "123-456-7890"
    end

    test ~s(the string "30" and the number 30 stay distinct) do
      encrypted = Payload.encrypt_payload(%{"s" => "30", "n" => 30})

      # Distinct plaintexts ("\"30\"" vs "30") give distinct markers.
      assert encrypted["s"] == "enc:b64:IjMwIg"
      assert encrypted["n"] == "enc:b64:MzA"

      decrypted = Payload.decrypt_payload(encrypted)
      assert decrypted["s"] === "30"
      assert decrypted["n"] === 30
    end

    test "booleans, null, unicode, empty values and arrays survive the round trip" do
      original = %{
        "true" => true,
        "false" => false,
        "null" => nil,
        "unicode" => "héllo 👋 œuvre",
        "empty_string" => "",
        "empty_object" => %{},
        "empty_array" => [],
        "array" => [1, "two", %{"three" => 3}, nil, true]
      }

      encrypted = Payload.encrypt_payload(original)

      # Spot-check hand-computed markers so the encryption side is anchored to
      # real values, not merely consistent with itself.
      assert encrypted["true"] == "enc:b64:dHJ1ZQ"
      assert encrypted["null"] == "enc:b64:bnVsbA"
      assert encrypted["empty_string"] == "enc:b64:IiI"
      assert encrypted["empty_object"] == "enc:b64:e30"

      decrypted = Payload.decrypt_payload(encrypted)
      assert decrypted == original
      assert decrypted["null"] === nil
      assert decrypted["empty_array"] === []
    end
  end

  describe "RiotTakeHome.Cipher.AesGcm" do
    test "is non-deterministic, round-trips, and rejects tampering" do
      plaintext = JSON.encode!(%{"big" => 12_345_678_901_234_567_890, "s" => "30"})

      ciphertext = AesGcm.encrypt(plaintext)
      # fresh random nonce per value: same plaintext, different ciphertext
      refute AesGcm.encrypt(plaintext) == ciphertext

      assert AesGcm.decrypt(ciphertext) == {:ok, plaintext}

      # flip one character inside the nonce region: the GCM tag must fail
      # closed with :error, never raise
      <<head::binary-size(5), char, rest::binary>> = ciphertext
      replacement = if char == ?A, do: ?B, else: ?A
      tampered = <<head::binary, replacement, rest::binary>>
      assert AesGcm.decrypt(tampered) == :error
    end
  end
end
