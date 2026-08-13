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

  # The false-positive table, first half: strings that are NOT transformed.
  # Detection replaces a string only when all four conditions hold — strict
  # standard base64, valid UTF-8, the integer bound, valid JSON — and each of
  # these fails at least one of them, so /decrypt returns every one strictly
  # unchanged. Verified with python (base64.b64decode, bytes.decode,
  # json.loads), never with the code under test:
  @unchanged [
    # decodes (to "F*-"), valid UTF-8, but not valid JSON
    "Riot",
    # decodes, but to <<0xB5, 0xEB, 0x2D>>, which is not valid UTF-8
    "test",
    # same: any 4-letter [a-z] word is valid base64, few decode to UTF-8
    "abcd",
    # the dashes sit outside the standard alphabet: not base64 at all
    "1998-11-19",
    # the space: not base64 either. "John" alone would still fail on JSON.
    "John Doe",
    # a real GitHub node_id: decodes to "012:Organization61430766",
    # valid UTF-8 but not valid JSON
    "MDEyOk9yZ2FuaXphdGlvbjYxNDMwNzY2",
    # decodes to "John Doe": a bare string is not a JSON document
    "Sm9obiBEb2U=",
    # decodes to "Hello": same
    "SGVsbG8=",
    # decodes to <<0xFF, 0xFE>>: invalid UTF-8
    "//4=",
    # missing padding: the strict decode rejects it outright
    "MzA"
  ]

  # All expected ciphertexts in this file were computed with python
  # (base64.b64encode over the JSON encoding of the value), never with the
  # code under test.
  describe "encrypt_payload/1" do
    test "the assignment example encrypts to the documented values" do
      assert Payload.encrypt_payload(@example) == %{
               "age" => "MzA=",
               "name" => "IkpvaG4gRG9lIg==",
               "contact" => "eyJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20iLCJwaG9uZSI6IjEyMy00NTYtNzg5MCJ9"
             }
    end
  end

  describe "decrypt_payload/1" do
    test "strings failing any detection condition pass through strictly unchanged" do
      payload = Map.new(Enum.with_index(@unchanged), fn {value, i} -> {"key_#{i}", value} end)

      assert Payload.decrypt_payload(payload) == payload
    end

    test "the accepted false positives: base64 of valid JSON is transformed" do
      # The second half of the table. These plaintext strings satisfy all four
      # conditions, so the heuristic cannot tell them from ciphertexts and
      # transforms them. This is the documented cost of detecting bare base64;
      # pinned here so the trade-off stays visible instead of implicit.
      assert Payload.decrypt_payload(%{"a" => "MzA=", "b" => "e30=", "c" => "dHJ1ZQ=="}) ==
               %{"a" => 30, "b" => %{}, "c" => true}
    end

    test "a ciphertext nested at depth 2 comes back unchanged" do
      original = %{"outer" => %{"inner" => "MzA="}}

      # Both operations act at depth 1 only: on decrypt the value of "outer"
      # is an object, not a string, so the nested value is never inspected.
      assert Payload.decrypt_payload(original) == original

      # Through a full round trip the nested string also survives verbatim
      # (it is encrypted as part of the depth-1 object, then restored).
      assert original |> Payload.encrypt_payload() |> Payload.decrypt_payload() == original
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

      # Distinct plaintexts ("\"30\"" vs "30") give distinct ciphertexts.
      assert encrypted["s"] == "IjMwIg=="
      assert encrypted["n"] == "MzA="

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

      # Spot-check hand-computed ciphertexts so the encryption side is
      # anchored to real values, not merely consistent with itself.
      assert encrypted["true"] == "dHJ1ZQ=="
      assert encrypted["null"] == "bnVsbA=="
      assert encrypted["empty_string"] == "IiI="
      assert encrypted["empty_object"] == "e30="

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
