defmodule RiotTakeHome.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    port = Application.fetch_env!(:riot_take_home, :port)
    children = [{Bandit, plug: RiotTakeHome.Router, scheme: :http, port: port}]
    Supervisor.start_link(children, strategy: :one_for_one, name: RiotTakeHome.Supervisor)
  end
end
