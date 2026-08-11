# --- Build stage: compile the release on the versions pinned in .tool-versions.
FROM elixir:1.19.5-otp-28-alpine AS build

ENV MIX_ENV=prod
WORKDIR /app

RUN mix local.hex --force && mix local.rebar --force

# Dependencies first, so source edits do not invalidate the deps cache.
COPY mix.exs mix.lock ./
RUN mix deps.get --only prod

COPY config config
RUN mix deps.compile

COPY lib lib
RUN mix compile --warnings-as-errors && mix release

# --- Run stage: bare Alpine (same minor as the build image, so the crypto NIF
# finds a matching libcrypto), non-root user, no sources, no build toolchain.
FROM alpine:3.23 AS app

RUN apk add --no-cache libstdc++ ncurses-libs openssl && \
    addgroup -S riot && adduser -S riot -G riot

WORKDIR /app
COPY --from=build --chown=riot:riot /app/_build/prod/rel/riot_take_home ./

USER riot
ENV HOME=/app

# A missing SIGNING_SECRET is a configuration error, not a VM fault: fail with
# the message from config/runtime.exs instead of dumping the emulator state.
ENV ERL_CRASH_DUMP_SECONDS=0

# The port is read at runtime from PORT (config/runtime.exs); 4000 is the default.
EXPOSE 4000

# SIGNING_SECRET must be provided at run time; the release refuses to boot without it.
CMD ["bin/riot_take_home", "start"]
