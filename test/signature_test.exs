defmodule RiotTakeHome.SignatureTest do
  use ExUnit.Case, async: true

  alias RiotTakeHome.Canonical
  alias RiotTakeHome.Signer
  alias RiotTakeHome.Signer.HmacSha256
  alias RiotTakeHome.Signer.HmacSha512

  describe "sign/1" do
    test "the two key orders of the assignment payload give the same signature" do
      a = JSON.decode!(~s({"message":"Hello World","timestamp":1616161616}))
      b = JSON.decode!(~s({"timestamp":1616161616,"message":"Hello World"}))

      assert Signer.sign(a) == Signer.sign(b)

      # Literal value computed independently, never with the code under test:
      #
      #   python3 -c 'import hmac, hashlib
      #   print(hmac.new(b"test-only-secret",
      #       b"{\"message\":\"Hello World\",\"timestamp\":1616161616}",
      #       hashlib.sha256).hexdigest())'
      #
      # A wrong canonical form that is merely self-consistent cannot satisfy
      # this assertion.
      assert Signer.sign(a) ==
               "c8ee4bcd1ab5ebe989aa82e42330f6ccb17df79423ec4c64ba39fcbc296b36f7"
    end

    test "large integers one apart sign differently" do
      # Both numbers round to the same IEEE-754 double, 1.2345678901234567e19.
      # A canonicalisation that normalises numbers through a float therefore
      # signs these two payloads identically: a demonstrable security defect,
      # since two distinct transfer ids would share one valid signature.
      # Exact arbitrary-precision integers keep them apart.
      a = JSON.decode!(~s({"transfer_id":12345678901234567890,"amount":100}))
      b = JSON.decode!(~s({"transfer_id":12345678901234567891,"amount":100}))

      assert Canonical.encode(a) == ~s({"amount":100,"transfer_id":12345678901234567890})
      assert Canonical.encode(b) == ~s({"amount":100,"transfer_id":12345678901234567891})
      refute Signer.sign(a) == Signer.sign(b)
    end

    test "1 and 1.0 do not sign the same" do
      # The assumed flip side of the exactness above: numbers are never
      # normalised, so the integer 1 and the float 1.0 are different signing
      # inputs. This is the price paid for refusing the float collision in
      # the previous test: a documented trade-off, not an accident.
      assert Canonical.encode(%{"a" => 1}) == ~s({"a":1})
      assert Canonical.encode(%{"a" => 1.0}) == ~s({"a":1.0})
      refute Signer.sign(%{"a" => 1}) == Signer.sign(%{"a" => 1.0})
    end
  end

  describe "valid?/2" do
    test "sign then verify passes; any alteration fails; no input crashes" do
      data = %{"message" => "Hello World", "timestamp" => 1_616_161_616}
      signature = Signer.sign(data)

      assert Signer.valid?(data, signature)

      # altered signature (last character flipped) must fail
      head = binary_part(signature, 0, byte_size(signature) - 1)
      last = binary_part(signature, byte_size(signature) - 1, 1)
      altered = head <> if last == "A", do: "B", else: "A"
      refute Signer.valid?(data, altered)

      # altered data must fail against the original signature
      refute Signer.valid?(%{"message" => "Hello World", "timestamp" => 1_616_161_617}, signature)

      # wrong-size signature: :crypto.hash_equals/2 raises on differing sizes,
      # so this exercises the size guard: false, never an exception
      refute Signer.valid?(data, "abc")
      refute Signer.valid?(data, "")

      # non-string signatures are invalid, never a crash
      refute Signer.valid?(data, 42)
      refute Signer.valid?(data, nil)
      refute Signer.valid?(data, %{})
    end
  end

  describe "the signature scheme is replaceable" do
    # The assignment asks for the signature algorithm to be swappable, exactly as
    # it does for the cipher. Swapping the config is the whole change: no other
    # module is touched. These tests run against the second implementation
    # directly, so they fail if the seam stops working.
    test "HMAC-SHA512 signs and verifies through the same behaviour" do
      message = "{\"a\":1}"
      key = "test-only-secret"

      signature = HmacSha512.sign(message, key)

      assert HmacSha512.verify(message, key, signature)
      refute HmacSha512.verify("{\"a\":2}", key, signature)
    end

    test "a SHA-256 signature is rejected by SHA-512 on length, without raising" do
      message = "{\"a\":1}"
      key = "test-only-secret"

      short = HmacSha256.sign(message, key)
      long = HmacSha512.sign(message, key)

      # lowercase hex: two characters per digest byte
      assert byte_size(short) == 64
      assert byte_size(long) == 128
      # hash_equals/2 raises on differing sizes; the guard has to come first.
      refute HmacSha512.verify(message, key, short)
      refute HmacSha256.verify(message, key, long)
    end
  end
end
