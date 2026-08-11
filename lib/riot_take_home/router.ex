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
      :error -> object_required(conn)
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
      :error -> object_required(conn)
    end
  end

  defp fetch_object(%Plug.Conn{body_params: %{"_json" => object}}) when is_map(object),
    do: {:ok, object}

  defp fetch_object(_conn), do: :error

  defp object_required(conn), do: error(conn, 400, "request body must be a JSON object")

  defp error(conn, status, message), do: send_json(conn, status, %{"error" => message})

  defp send_json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, JSON.encode_to_iodata!(body))
  end
end
