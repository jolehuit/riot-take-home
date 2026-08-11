defmodule RiotTakeHome.Cipher do
  @moduledoc """
  Behaviour for a reversible value cipher, plus the ciphertext marker.

  Marker format: `enc:<alg_id>:<data>`. The algorithm id travels with the
  value, so detection at decrypt time is exact instead of heuristic, and a
  second algorithm can coexist with the first without any migration.
  """

  @callback id() :: String.t()
  @callback encrypt(plaintext :: binary()) :: binary()
  @callback decrypt(data :: binary()) :: {:ok, binary()} | :error

  @prefix "enc:"

  # Every cipher `/decrypt` can recognise. `active/0` (which one `/encrypt`
  # uses) is the real configuration seam; the set of readable formats does not
  # vary by environment, so it lives here rather than in config.
  @ciphers [RiotTakeHome.Cipher.Base64, RiotTakeHome.Cipher.AesGcm]

  @doc "The cipher `/encrypt` uses, resolved from application config."
  @spec active() :: module()
  def active, do: Application.fetch_env!(:riot_take_home, :cipher)

  @doc "Every cipher `/decrypt` recognises, keyed by algorithm id."
  @spec known() :: %{optional(String.t()) => module()}
  def known, do: Map.new(@ciphers, fn cipher -> {cipher.id(), cipher} end)

  @doc "Wraps encrypted data in the marker of the given cipher."
  @spec wrap(module(), binary()) :: binary()
  def wrap(cipher, data), do: @prefix <> cipher.id() <> ":" <> data

  @doc """
  Splits a marked value into `{:ok, alg_id, data}`.

  Returns `:error` for any value that does not carry a well-formed marker;
  whether the id is known is the caller's decision.
  """
  @spec unwrap(term()) :: {:ok, String.t(), binary()} | :error
  def unwrap(@prefix <> rest) do
    case String.split(rest, ":", parts: 2) do
      [id, data] when id != "" -> {:ok, id, data}
      _ -> :error
    end
  end

  def unwrap(_other), do: :error
end
