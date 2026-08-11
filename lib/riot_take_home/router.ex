defmodule RiotTakeHome.Router do
  @moduledoc """
  HTTP layer: the four POST endpoints over the crypto core.

  `Plug.Parsers` (standard-library `JSON`) decodes the body before dispatch.
  A wrong content-type, an oversized body and malformed JSON all raise inside
  the parser; `parse/2` rescues the three locally and answers 415, 413 and 400,
  so a request body never reaches the logs. `Plug.ErrorHandler` stays as a
  last-resort net that returns a generic JSON error, never an execution trace.

  `nest_all_json: true` nests the decoded root under `"_json"`, which tells a
  JSON object apart from a top-level array, string, number, or an empty body.
  """

  use Plug.Router
  use Plug.ErrorHandler

  alias RiotTakeHome.Payload
  alias RiotTakeHome.Signer

  @max_body_bytes 1_048_576

  # The body limit bounds bytes, not CPU. Turning a bignum back into decimal is
  # quadratic in its length, and every endpoint re-encodes what it was given, so
  # one 1 MB integer literal costs ~24 s where 1 MB of text costs 1 ms. Bounding
  # the digits bounds the whole worst case: cost grows as body size times this
  # limit, which puts a full 1 MiB body under 50 ms. A 1000-digit integer is
  # about 3300 bits, past any real value, so exact arithmetic is untouched.
  @max_digits 1000
  @max_integer Integer.pow(10, @max_digits)

  @parser_opts Plug.Parsers.init(
                 parsers: [:json],
                 json_decoder: JSON,
                 nest_all_json: true,
                 length: @max_body_bytes
               )

  plug :match
  plug :parse
  plug :dispatch

  post "/encrypt", do: transform(conn, &Payload.encrypt_payload/1)
  post "/decrypt", do: transform(conn, &Payload.decrypt_payload/1)

  post "/sign" do
    case fetch_object(conn) do
      {:ok, object} -> send_json(conn, 200, %{"signature" => Signer.sign(object)})
      {:error, message} -> error(conn, 400, message)
    end
  end

  post "/verify" do
    with {:ok, object} <- fetch_object(conn),
         {:ok, data} when is_map(data) <- Map.fetch(object, "data"),
         {:ok, signature} when is_binary(signature) <- Map.fetch(object, "signature"),
         true <- Signer.valid?(data, signature) do
      send_resp(conn, 204, "")
    else
      _ -> error(conn, 400, "invalid signature or malformed verify request")
    end
  end

  # The four routes exist and only answer POST, so any other method on them is
  # a 405 with Allow, per RFC 9110, rather than pretending the path is unknown.
  match "/encrypt", do: method_not_allowed(conn)
  match "/decrypt", do: method_not_allowed(conn)
  match "/sign", do: method_not_allowed(conn)
  match "/verify", do: method_not_allowed(conn)

  match _ do
    error(conn, 404, "not found")
  end

  @impl Plug.ErrorHandler
  @spec handle_errors(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def handle_errors(conn, _error) do
    message = if (conn.status || 500) >= 500, do: "internal server error", else: "bad request"
    send_json(conn, conn.status || 500, %{"error" => message})
  end

  # Parses the JSON body. A missing content-type passes through (the body stays
  # unparsed and the handler answers 400 "must be a JSON object"); a wrong one,
  # an oversized body, or malformed JSON are rescued here so the raw body is
  # never re-raised into the logs.
  defp parse(conn, _opts) do
    Plug.Parsers.call(conn, @parser_opts)
  rescue
    Plug.Parsers.UnsupportedMediaTypeError ->
      conn |> error(415, "content-type must be application/json") |> halt()

    Plug.Parsers.RequestTooLargeError ->
      conn |> error(413, "request body exceeds the limit of #{@max_body_bytes} bytes") |> halt()

    Plug.Parsers.ParseError ->
      conn |> error(400, "malformed JSON body") |> halt()
  end

  defp transform(conn, fun) do
    case fetch_object(conn) do
      {:ok, object} -> send_json(conn, 200, fun.(object))
      {:error, message} -> error(conn, 400, message)
    end
  end

  defp fetch_object(%Plug.Conn{body_params: %{"_json" => object}}) when is_map(object) do
    if bounded?(object),
      do: {:ok, object},
      else: {:error, "an integer exceeds #{@max_digits} digits"}
  end

  defp fetch_object(_conn), do: {:error, "request body must be a JSON object"}

  defp bounded?(int) when is_integer(int), do: int < @max_integer and int > -@max_integer
  defp bounded?(map) when is_map(map), do: Enum.all?(map, fn {_key, value} -> bounded?(value) end)
  defp bounded?(list) when is_list(list), do: Enum.all?(list, &bounded?/1)
  defp bounded?(_other), do: true

  defp method_not_allowed(conn) do
    conn
    |> put_resp_header("allow", "POST")
    |> error(405, "method not allowed, use POST")
  end

  defp error(conn, status, message), do: send_json(conn, status, %{"error" => message})

  defp send_json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, JSON.encode_to_iodata!(body))
  end
end
