# --- cleanliness and enjoyability
# TODOINPROGRESS unverbosify inspects
# TODO easy code edit tools
# --- performance
# TODO dont rebuild untouched files (imp this)
# TODO files in /dev/shm
defmodule Worm do
  def init(dir_name, app_name, module_name) do
    # out folder is completely tmp
    # nothing valuable should b stored there

    System.cmd("rm", ["-f", "-r", "#{dir_name}.bak"])
    System.cmd("mv", [dir_name, "#{dir_name}.bak"])
    System.cmd("mix", ["phx.new", dir_name, "--app", app_name, "--module", module_name, "--no-webpack", "--no-html", "--binary-id", "--no-install"])

    if File.exists?("#{dir_name}.bak/mix.lock") do
      IO.puts("INFO keeping old deps")

      System.cmd("cp", ["#{dir_name}.bak/mix.lock", "#{dir_name}/"])
      System.cmd("cp", ["-r", "#{dir_name}.bak/deps", "#{dir_name}/"])
    end

    if File.exists?("#{dir_name}.bak/_build") do
      IO.puts("INFO keeping old _build")

      System.cmd("cp", ["-r", "#{dir_name}.bak/_build", "#{dir_name}/"])
    end

    if File.exists?("#{dir_name}.bak/.idea") do
      IO.puts("INFO keeping old ide files")

      System.cmd("cp", ["-r", "#{dir_name}.bak/.idea", "#{dir_name}/"])
      :os.cmd('cp #{dir_name}.bak/*.iml #{dir_name}/')
    end

    System.cmd("mkdir", ["#{dir_name}/lib/#{app_name}/schemas"])
    System.cmd("mkdir", ["#{dir_name}/lib/#{app_name}/modules"])

    # System.cmd("sed", ["-i", "17d", "#{dir_name}/config/config.exs"])
    # System.cmd("sed", ["-i", "16a\\  secret_key_base: System.get_env(\\\"SECRET_KEY_BASE\\\"),", "#{dir_name}/config/config.exs"])
    # System.cmd("sed", ["-i", "20d", "#{dir_name}/config/config.exs"])
    # System.cmd("sed", ["-i", "19a\\  live_view: [signing_salt: System.get_env(\\\"SIGNING_SALT\\\")]", "#{dir_name}/config/config.exs"])

    System.cmd("sed", ["-i", "5d", "#{dir_name}/config/dev.exs"])
    System.cmd("sed", ["-i", "4a\\  username: System.get_env(\\\"DB_USERNAME\\\"),", "#{dir_name}/config/dev.exs"])
    System.cmd("sed", ["-i", "6d", "#{dir_name}/config/dev.exs"])
    System.cmd("sed", ["-i", "5a\\  password: System.get_env(\\\"DB_PASSWORD\\\"),", "#{dir_name}/config/dev.exs"])
    System.cmd("sed", ["-i", "7d", "#{dir_name}/config/dev.exs"])
    System.cmd("sed", ["-i", "6a\\  database: System.get_env(\\\"DB_NAME\\\"),", "#{dir_name}/config/dev.exs"])
    System.cmd("sed", ["-i", "8d", "#{dir_name}/config/dev.exs"])
    System.cmd("sed", ["-i", "7a\\  hostname: System.get_env(\\\"DB_HOST\\\"),", "#{dir_name}/config/dev.exs"])
    System.cmd("sed", ["-i", "10d", "#{dir_name}/config/dev.exs"])
    System.cmd("sed", ["-i", "9a\\  pool_size: 4", "#{dir_name}/config/dev.exs"])
    System.cmd("sed", ["-i", "20d", "#{dir_name}/config/dev.exs"])
    System.cmd("sed", ["-i", "19a\\  debug_errors: false,", "#{dir_name}/config/dev.exs"])

    # TODO sockets

    w =
"defmodule #{module_name}Web.FallbackController do
  use #{module_name}Web, :controller

  def call(conn, err) do
    err = err
          |> IO.inspect()
          |> elem(1)

    err = case err do
      {:error, %Ecto.Changeset{} = chg} ->
        chg.errors
        |> hd
        |> elem(1)
        |> elem(0)
      %Ecto.InvalidChangesetError{} = chg_err ->
        chg_err.changeset.errors
        |> hd
        |> elem(1)
        |> elem(0)
      %Ecto.ConstraintError{constraint: c, type: t} ->
        \\\"\#{t} \#{c}\\\"
      %Postgrex.Error{postgres: %{constraint: c, code: t}} ->
        \\\"\#{t} \#{c}\\\"
      %RuntimeError{} = run_err ->
        run_err.message
      msg ->
        if String.valid?(msg) do
          msg
        else
          \\\"!\\\"
        end
    end

    if conn do
      conn
      |> put_status(:bad_request)
      |> json(%{error: err})
    else
      %{reason: err}
    end
  end
end"

    :os.cmd('echo "#{w}" > #{dir_name}/lib/#{app_name}_web/controllers/fallback_controller.ex')

    w =
"# General application configuration
use Mix.Config

config :#{app_name},
  namespace: #{module_name},
  ecto_repos: [#{module_name}.Repo],
  generators: [binary_id: true]

# Configures the endpoint
config :#{app_name}, #{module_name}Web.Endpoint,
  url: [host: \"localhost\"],
  secret_key_base: System.get_env(\"SECRET_KEY_BASE\"),
  render_errors: [view: #{module_name}Web.ErrorView, accepts: ~w(json), layout: false],
  pubsub_server: #{module_name}.PubSub,
  live_view: [signing_salt: System.get_env(\"SIGNING_SALT\")]

# Configures Elixir's Logger
config :logger, :console,
  format: \"$time $metadata[$level] $message\\n\",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config \"\#{Mix.env()}.exs\""

    File.write!("#{dir_name}/config/config.exs", w)
  end

  def parse(file_name, dir_name, app_name, module_name, agent) do
    lines = file_name
            |> File.read!
            |> String.split("\n")

    lines
    |> Enum.with_index(1)
    |> Enum.reduce({nil}, fn ({cur, i}, {extend}) ->
      if extend do
        {headers, body, i} = extend

        #  cur == ""
        if cur == "<==" do
          case hd(headers) do
            "s" ->
              parse_schema(tl(headers), body, file_name, i, dir_name, app_name, module_name, agent)
            "r" ->
              parse_route(tl(headers), body, file_name, i, dir_name, app_name, module_name, agent)
            "n" ->
              parse_snippet(tl(headers), body, file_name, i, dir_name, app_name, module_name, agent)
          end

          {nil}
        else
          cur = if cur != "" do
            cur
            |> to_charlist
            |> tl |> tl
            |> to_string
          else
            ""
          end

          {{headers, body <> cur <> "\n", i}}
        end
      else
        if cur != "" do
          tokens = cur
                   |> String.split(" ", trim: true)

          case hd(tokens) do
            "q" ->
              IO.puts("INFO #{file_name}:#{i} found requirement")

              parse_requirement(tl(tokens), file_name, i, dir_name, app_name, module_name)

              {nil}
            "c" ->
              IO.puts("INFO #{file_name}:#{i} found shortcut")

              parse_shortcut(tl(tokens), file_name, i, agent)

              {nil}
            "n" ->
              IO.puts("INFO #{file_name}:#{i} found snippet")

              {{tokens, "", i}}
            "s" ->
              IO.puts("INFO #{file_name}:#{i} found schema")

              {{tokens, "", i}}
            "r" ->
              IO.puts("INFO #{file_name}:#{i} found route")

              {{tokens, "", i}}
            "--" ->
              IO.puts("INFO #{file_name}:#{i} ignoring comment")

              {nil}
            _ ->
              raise "ERROR #{file_name}:#{i} unknown token #{hd(tokens)}"
          end
        else
          {extend}
        end
      end
    end)
  end

  def parse_custom(file_name, dir_name, app_name, module_name, agent) do
    lines = file_name
            |> File.read!
            |> String.split("\n")

    {head, rest, _} = Enum.reduce(lines, {"", "", false}, fn (cur, {head, rest, seen}) ->
      if cur == "==>" do
        {head, rest, true}
      else
        if seen do
          {head, rest <> cur <> "\n", seen}
        else
          {head <> cur <> "\n", rest, seen}
        end
      end
    end)

    rest = rest
           |> apply_multiline(agent)
           |> apply_shortcuts(agent)
           |> String.trim_trailing()

    p = file_name
        |> String.split("/")
        |> Enum.reverse()
        |> hd
        |> String.split(".")
        |> Enum.reverse()
        |> tl
        |> Enum.reverse()
        |> Enum.join(".")

    uuid = UUID.uuid4()

    file = "/tmp/worm-parse-#{uuid}/#{p}"

    System.cmd("mkdir", ["/tmp/worm-parse-#{uuid}"])

    File.write(file, rest)

    head
    |> String.split("\n", trim: true)
    |> Enum.each(fn (cur) ->
      x = cur
          |> apply_shortcuts(agent)
          |> String.replace("&cur", file)
          |> String.replace("&ins-beg", "sed -i '$ ! s/$/\\\\/' #{file} && sed -i \"")
          |> String.replace("&ins-end", "i$(cat #{file})\"")
          |> String.replace("&{", "sed -i '$ ! s/$/\\\\/' #{file} && sed -i \"")
          |> String.replace("&}", "i$(cat #{file})\"")

      x
      |> to_charlist
      |> :os.cmd
    end)

    System.cmd("rm", ["-f", "-r", "/tmp/worm-parse-#{uuid}"])
  end

  defp parse_requirement(headers, file_name, num, dir_name, app_name, module_name) do
    case headers do
      [name | extra] ->
        {version, override} = case extra do
          [version, override | extra] ->
            if extra != [] do
              IO.puts("WARN #{file_name}:#{num} ignored extra arguments")
            end

            {"~> #{version}", ", override: true"}
          [version] ->
            {"~> #{version}", ""}
          [] ->
            {">= 0.0.0", ""}
        end

        System.cmd("sed", ["-i", "36i\\      {:#{name}, \"#{version}\"#{override}},", "#{dir_name}/mix.exs"])
      [] ->
        raise "ERROR #{file_name}:#{num} no arguments given"
    end
  end

  defp parse_shortcut(headers, file_name, num, agent) do
    case headers do
      [name, replace | extra] ->
        if extra != [] do
          IO.puts("WARN #{file_name}:#{num} ignored extra arguments")
        end

        agent
        |> Agent.update(fn (cur) ->
          cur
          |> Map.put(:shortcuts, [{"&" <> name, replace} | cur.shortcuts])
        end)
    end
  end

  defp parse_snippet(headers, body, file_name, num, dir_name, app_name, module_name, agent) do
    case headers do
      [name | extra] ->
        if extra != [] do
          IO.puts("WARN #{file_name}:#{num} ignored extra arguments")
        end

        agent
        |> Agent.update(fn (cur) ->
          lines = body
                  |> String.split("\n")

          snippets = cur.snippets
                     |> Map.put(name, lines)

          cur
          |> Map.put(:snippets, snippets)
        end, :infinity)
    end
  end

  defp parse_schema(headers, body, file_name, num, dir_name, app_name, module_name, agent) do
    case headers do
      [name | extra] ->
        if extra != [] do
          IO.puts("WARN #{file_name}:#{num} ignored extra arguments")
        end

        lines = body
                |> String.split("\n")

        {mig_lines, sch_lines, indexes, uniq_indexes, constraints, _} = lines
                                                                        |> Enum.with_index(
        )
        |> Enum.reduce({[], [], %{}, %{}, [], nil}, fn ({cur, i}, {mig_lines, sch_lines, indexes, uniq_indexes, constraints, extend}) ->
          if extend do
            {headers, body, i} = extend

            if cur == "" do
              {mig_line, sch_line, new_indexes, new_uniq_indexes, new_constraints} = parse_schema_field(headers, body, file_name, i, module_name, agent)

              indexes = Enum.reduce(new_indexes, indexes, fn ({field, level}, acc) ->
                existing = if acc[level] === nil do
                  []
                else
                  acc[level]
                end

                acc
                |> Map.put(level, [field | existing])
              end)

              uniq_indexes = Enum.reduce(new_uniq_indexes, uniq_indexes, fn ({field, level}, acc) ->
                existing = if acc[level] === nil do
                  []
                else
                  acc[level]
                end

                acc
                |> Map.put(level, [field | existing])
              end)

              { (if mig_line, do: [mig_line | mig_lines], else: mig_lines),
                (if sch_line, do: [sch_line | sch_lines], else: sch_lines),
              indexes, uniq_indexes, new_constraints ++ constraints, nil}
            else
              cur = cur
                    |> to_charlist
                    |> tl |> tl
                    |> to_string

              {mig_lines, sch_lines, indexes, uniq_indexes, constraints, {headers, body <> cur <> "\n", i}}
            end
          else
            if cur != "" do
              tokens = cur
                       |> String.split(" ", trim: true)

              if length(tokens) <= 2 do
                {mig_line, sch_line, new_indexes, new_uniq_indexes, new_constraints} = parse_schema_field(tokens, nil, file_name, num + i, module_name, agent)

                indexes = Enum.reduce(new_indexes, indexes, fn ({field, level}, acc) ->
                  existing = if acc[level] === nil do
                    []
                  else
                    acc[level]
                  end

                  acc
                  |> Map.put(level, [field | existing])
                end)

                uniq_indexes = Enum.reduce(new_uniq_indexes, uniq_indexes, fn ({field, level}, acc) ->
                  existing = if acc[level] === nil do
                    []
                  else
                    acc[level]
                  end

                  acc
                  |> Map.put(level, [field | existing])
                end)

                { (if mig_line, do: [mig_line | mig_lines], else: mig_lines),
                  (if sch_line, do: [sch_line | sch_lines], else: sch_lines),
                  indexes, uniq_indexes, new_constraints ++ constraints, nil}
              else
                {mig_lines, sch_lines, indexes, uniq_indexes, constraints, {tokens, "", num + i}}
              end
            else
              {mig_lines, sch_lines, indexes, uniq_indexes, constraints, extend}
            end
          end
        end)

        mig_lines = Enum.reverse(mig_lines)
        sch_lines = Enum.reverse(sch_lines)

        idx = Agent.get_and_update(agent, fn (cur) ->
          next = cur
                 |> Map.put(:mig_idx, cur.mig_idx + 1)

          {cur.mig_idx, next}
        end, :infinity)

        file = "#{dir_name}/priv/repo/migrations/#{idx}_create_#{String.downcase(name)}.exs"

        :os.cmd('echo "defmodule #{module_name}.Repo.Migrations.Create#{String.upcase(name)} do" > #{file}')
        :os.cmd('echo "  use Ecto.Migration" >> #{file}')
        :os.cmd('echo "" >> #{file}')
        :os.cmd('echo "  def change do" >> #{file}')
        :os.cmd('echo "    create table(:#{name}, primary_key: false) do" >> #{file}')

        m = Enum.reduce(mig_lines, "", fn (cur, acc) ->
          acc <> "      " <> cur <> "\n"
        end)
        |> String.trim()

        :os.cmd('echo "      #{m}" >> #{file}')
        :os.cmd('echo "    end" >> #{file}')

        idx_conflicts = %{}

        if length(Map.keys(uniq_indexes)) > 0 do
          :os.cmd('echo "" >> #{file}')
        end

        idx_conflicts = Enum.reduce(uniq_indexes, idx_conflicts, fn ({key, val}, acc) ->
          fields = val
                   |> Enum.sort()

          if key == -1 do
            Enum.reduce(fields, acc, fn (cur, acc) ->
              if acc[{name, [cur]}] === nil do
                :os.cmd('echo "    create unique_index(:#{name}, [:#{cur}])" >> #{file}')

                acc
                |> Map.put({name, [cur]}, true)
              else
                acc
              end
            end)
          else
            if acc[{name, fields}] === nil do
              sep = Enum.reduce(fields, "", fn (cur, acc) ->
                acc <> ":" <> cur <> "  "
              end)
              |> String.trim()
              |> String.replace("  ", ", ")

              :os.cmd('echo "    create unique_index(:#{name}, [#{sep}])" >> #{file}')

              acc
              |> Map.put({name, fields}, true)
            else
              acc
            end
          end
        end)

        if length(Map.keys(indexes)) > 0 do
          :os.cmd('echo "" >> #{file}')
        end

        Enum.reduce(indexes, idx_conflicts, fn ({key, val}, acc) ->
          fields = val
                   |> Enum.sort()

          if key == -1 do
            fields
            |> Enum.each(fn (cur) ->
              if acc[{name, [cur]}] === nil do
                :os.cmd('echo "    create index(:#{name}, [:#{cur}])" >> #{file}')

                acc
                |> Map.put({name, [cur]}, true)
              else
                acc
              end
            end)
          else
            if acc[{name, fields}] === nil do
              sep = Enum.reduce(fields, "", fn (cur, acc) ->
                acc <> ":" <> cur <> "  "
              end)
              |> String.trim()
              |> String.replace("  ", ", ")

              :os.cmd('echo "    create index(:#{name}, [#{sep}])" >> #{file}')

              acc
              |> Map.put({name, fields}, true)
            else
              acc
            end
          end
        end)

        if constraints != [] do
          :os.cmd('echo "" >> #{file}')
        end

        constraints
        |> Enum.reverse()
        |> Enum.each(fn ({cname, check}) ->
          File.write(file, "    create constraint(:#{name}, :#{cname}, check: \"#{check}\")\n", [:append])
        end)

        :os.cmd('echo "  end" >> #{file}')
        :os.cmd('echo "end" >> #{file}')

        file = "#{dir_name}/lib/#{app_name}/schemas/#{String.downcase(name)}.ex"

        :os.cmd('echo "defmodule #{module_name}.#{String.upcase(name)} do" > #{file}')
        :os.cmd('echo "  use Ecto.Schema" >> #{file}')
        :os.cmd('echo "" >> #{file}')
        :os.cmd('echo "  @primary_key false" >> #{file}')
        :os.cmd('echo "  schema \\\"#{name}\\\" do" >> #{file}')

        s = Enum.reduce(sch_lines, "", fn (cur, acc) ->
          acc <> "    " <> cur <> "\n"
        end)
        |> String.trim()

        :os.cmd('echo "    #{s}" >> #{file}')
        :os.cmd('echo "  end" >> #{file}')
        :os.cmd('echo "end" >> #{file}')
    end
  end

  defp parse_schema_field(headers, body, file_name, num, module_name, agent) do
    [field, type | _] = headers

    field = field
            |> apply_shortcuts(agent)

    {mig_type, sch_type, indexes, uniq_indexes, constraints} = case type do
      "&int" ->
        {":integer", ":integer", [], [], []}
      "&long" ->
        {":bigint", ":integer", [], [], []}
      "&str" ->
        {":string", ":string", [], [], [{"#{field}_nonempty_string", "#{field} != ''"}]}
      "&str{" <> dat ->
        dat = dat
              |> String.reverse()

        "}" <> dat = dat

        len = dat
              |> String.reverse()
              |> String.to_integer()

        {":string, size: #{len}", ":string", [], [], [{"#{field}_nonempty_string", "#{field} != ''"}]}
      "&txt" ->
        {":text", ":string", [], [], [{"#{field}_nonempty_string", "#{field} != ''"}]}
      "&txt{" <> dat ->
        dat = dat
              |> String.reverse()

        "}" <> dat = dat

        len = dat
              |> String.reverse()
              |> String.to_integer()

        {":text", ":string", [], [], [{"#{field}_strlen_lte_#{len}", "length(#{field}) <= #{len}"}, {"#{field}_nonempty_string", "#{field} != ''"}]}
      "&r{" <> dat ->
        dat = dat
              |> String.reverse()

        "}" <> dat = dat

        tk = dat
             |> String.reverse()
             |> String.split(",")

        [a, b, c] = tk

        {sub, a, _} = Enum.reduce(to_charlist(a), {0, '', false}, fn (cur, {acc, new, stop}) ->
          case cur do
            45 ->
              if !stop do
                {acc + 1, new, stop}
              else
                {acc, [cur | new], stop}
              end
            43 ->
              {acc, [cur | new], true}
            _ ->
              {acc, [cur | new], stop}
          end
        end)

        a = a
            |> Enum.reverse()
            |> to_string

        a = case a do
          "+" <> ext ->
            str = field
                  |> String.slice(0..(String.length(field) - 1 - 3 - sub))

            str <> ext
          _ ->
            a
        end

        case c do
          "UD" ->
            {"references(:#{a}, [type: :#{b}, on_update: :update_all, on_delete: :delete_all])", "#{module_name}.#{String.upcase(a)}, [foreign_key: :#{field}, type: :#{b}]", [{field, -1}], [], []}
          "Ud" ->
            {"references(:#{a}, [type: :#{b}, on_update: :update_all, on_delete: :nilify_all])", "#{module_name}.#{String.upcase(a)}, [foreign_key: :#{field}, type: :#{b}]", [{field, -1}], [], []}
          "uD" ->
            {"references(:#{a}, [type: :#{b}, on_update: :nilify_all, on_delete: :delete_all])", "#{module_name}.#{String.upcase(a)}, [foreign_key: :#{field}, type: :#{b}]", [{field, -1}], [], []}
          "ud" ->
            {"references(:#{a}, [type: :#{b}, on_update: :nilify_all, on_delete: :nilify_all])", "#{module_name}.#{String.upcase(a)}, [foreign_key: :#{field}, type: :#{b}]", [{field, -1}], [], []}
          "U" ->
            {"references(:#{a}, [type: :#{b}, on_update: :update_all])", "#{module_name}.#{String.upcase(a)}, [foreign_key: :#{field}, type: :#{b}]", [{field, -1}], [], []}
          "u" ->
            {"references(:#{a}, [type: :#{b}, on_update: :nilify_all])", "#{module_name}.#{String.upcase(a)}, [foreign_key: :#{field}, type: :#{b}]", [{field, -1}], [], []}
          "D" ->
            {"references(:#{a}, [type: :#{b}, on_delete: :delete_all])", "#{module_name}.#{String.upcase(a)}, [foreign_key: :#{field}, type: :#{b}]", [{field, -1}], [], []}
          "d" ->
            {"references(:#{a}, [type: :#{b}, on_delete: :nilify_all])", "#{module_name}.#{String.upcase(a)}, [foreign_key: :#{field}, type: :#{b}]", [{field, -1}], [], []}
          "" ->
            {"references(:#{a}, [type: :#{b}])", "#{module_name}.#{String.upcase(a)}, [foreign_key: :#{field}, type: :#{b}]", [{field, -1}], [], []}
        end
      # TODO `` for type
      _ ->
        type_tokens = type
                      |> String.split(",")

        case type_tokens do
          [mig, sch] ->
            sch = case sch do
              "`" <> c ->
                c = c
                    |> String.reverse()

                "`" <> c = c

                c
                |> String.reverse()
              _ ->
                ":" <> sch
            end

            {":" <> mig, sch, [], [], []}
          [one] ->
            {":" <> one, ":" <> one, [], [], []}
        end
    end

    mig_type = mig_type
               |> apply_shortcuts(agent)

    sch_type = sch_type
               |> apply_shortcuts(agent)

    {mig_line, sch_line} = case field do
      "&id" ->
        {"add :id, #{mig_type}, primary_key: true", "field :id, #{sch_type}, [autogenerate: true, primary_key: true]"}
      "&ts{" <> dat ->
        dat = dat
              |> String.reverse()

        "}" <> dat = dat

        tk = dat
             |> String.reverse()
             |> String.split(",")

        [c] = tk

        case c do
          "CU" ->
            {"timestamps([type: #{mig_type}])", "timestamps([type: #{sch_type}])"}
          "C" ->
            {"timestamps([type: #{mig_type}, updated_at: false])", "timestamps([type: #{sch_type}, updated_at: false, updated_at_source: false])"}
          "U" ->
            {"timestamps([type: #{mig_type}, inserted_at: false])", "timestamps([type: #{sch_type}, inserted_at: false, inserted_at_source: false])"}
        end
      _ ->
        case type do
          "&r{" <> _ ->
            {"add :#{field}, #{mig_type}", "belongs_to :#{field}_assoc, #{sch_type}"}
          _ ->
            {"add :#{field}, #{mig_type}", "field :#{field}, #{sch_type}"}
        end
    end

    {indexes, uniq_indexes} = if body do
      lines = body
              |> String.split("\n")

      lines
      |> Enum.with_index()
      |> Enum.reduce({indexes, uniq_indexes}, fn ({cur, i}, {indexes, uniq_indexes}) ->
        if cur != "" do
          tokens = cur
                   |> String.split(" ", trim: true)

          level = case tl(tokens) do
            [level] ->
              level
            [] ->
              -1
          end

          field = field
                  |> String.replace("&ts{C}", "inserted_at")
                  |> String.replace("&ts{U}", "updated_at")

          if field == "&ts{CU}" do
            case hd(tokens) do
              "ui" ->
                {indexes, [{"updated_at", level} | [{"inserted_at", level} | uniq_indexes]]}
              "i" ->
                {[{"updated_at", level} | [{"inserted_at", level} | indexes]], uniq_indexes}
            end
          else
            case hd(tokens) do
              "ui" ->
                {indexes, [{field, level} | uniq_indexes]}
              "i" ->
                {[{field, level} | indexes], uniq_indexes}
            end
          end
        else
          {indexes, uniq_indexes}
        end
      end)
    else
      {indexes, uniq_indexes}
    end

    {mig_line, sch_line, indexes, uniq_indexes, constraints}
  end

  defp parse_route(headers, body, file_name, num, dir_name, app_name, module_name, agent) do
    case headers do
      [method, path, op | extra] ->
        schema = case extra do
          [schema | extra] ->
            if extra != [] do
              IO.puts("WARN #{file_name}:#{num} ignored extra arguments")
            end

            schema
          [] ->
            nil
        end

        if path
           |> to_charlist
           |> hd == 47 do
          raise "ERROR #{file_name}:#{num} absolute paths aren't supported"
        end

        lines = body
                |> String.split("\n")

        {head, rest, _} = Enum.reduce(lines, {"", "", false}, fn (cur, {head, rest, seen}) ->
          if cur == "==>" do
            {head, rest, true}
          else
            if seen do
              {head, rest <> cur <> "\n", seen}
            else
              {head <> cur <> "\n", rest, seen}
            end
          end
        end)

        {vars, blocks} = case op do
          "C" ->
            {vars, blocks} = head
                             |> parse_create(schema, false, module_name, file_name, num, agent)

            # TODO more fields for 'after' stuff like imports (including manual imports)

            {vars, blocks}
          "Ct" ->
            {vars, blocks} = head
                             |> parse_create(schema, true, module_name, file_name, num, agent)

            {vars, blocks}
          "R" ->
            {[], []}
          "U" ->
            {[], []}
          "D" ->
            {[], []}
          "V" <> trail ->
            head
            |> parse_validate(trail, module_name, file_name, num, agent)
        end

        vars = Enum.filter(vars, fn (cur) ->
          case cur do
            {:noop, _} ->
              false
            _ ->
              true
          end
        end)
        |> Enum.reverse()

        blocks = Enum.reverse(blocks)

        p = path
            |> String.replace("/", "_")
            |> String.replace("-", "_")
            |> String.replace("+", "_")
            |> String.replace(":", "")

        file = "#{dir_name}/lib/#{app_name}/#{method}_#{String.downcase(p)}.ex"

        :os.cmd('echo "defmodule #{module_name}.#{String.upcase(method)}_#{String.upcase(p)} do" > #{file}')
        :os.cmd('echo "  import Ecto.Query, warn: false" >> #{file}')
        :os.cmd('echo "  alias Ecto.UUID" >> #{file}')
        :os.cmd('echo "  alias #{module_name}.Repo" >> #{file}')
        # TODO add more schemas custom
        if schema do
          :os.cmd('echo "" >> #{file}')
          :os.cmd('echo "  alias #{module_name}.#{String.upcase(schema)}" >> #{file}')
        end
        :os.cmd('echo "" >> #{file}')

        v = vars
            |> Enum.reduce("", fn ({_, cur}, acc) -> acc <> cur <> "  " end)
            |> String.trim()
            |> String.replace("  ", ", ")

        :os.cmd('echo "  def run!(#{v}) do" >> #{file}')

        b = Enum.reduce(blocks, "", fn (cur, acc) ->
          lines = cur
                  |> String.split("\n")

          acc <> Enum.reduce(lines, "", fn (cur, acc) ->
            acc <> "    " <> cur <> "\n"
          end)
        end)
        |> String.trim()

        File.write(file, "    #{b}", [:append])

        :os.cmd('echo "" >> #{file}')

        rest_lines = rest
                     |> apply_multiline(agent)
                     |> apply_shortcuts(agent)
                     |> String.replace("&@", v)
                     |> String.split("\n")

        # rest_lines = ["# custom code below" | ["" | rest_lines]]

        r = Enum.reduce(rest_lines, "", fn (cur, acc) ->
          acc <> "    " <> cur <> "\n"
        end)
        |> String.trim_trailing()

        File.write(file, "\n#{r}", [:append])

        :os.cmd('echo "" >> #{file}')
        :os.cmd('echo "  end" >> #{file}')
        :os.cmd('echo "end" >> #{file}')

        file = "#{dir_name}/lib/#{app_name}_web/controllers/#{method}_#{String.downcase(p)}_controller.ex"

        :os.cmd('echo "defmodule #{module_name}Web.#{String.upcase(method)}_#{String.upcase(p)}Controller do" > #{file}')
        :os.cmd('echo "  use #{module_name}Web, :controller" >> #{file}')
        :os.cmd('echo "" >> #{file}')
        :os.cmd('echo "  alias #{module_name}.#{String.upcase(method)}_#{String.upcase(p)}" >> #{file}')
        :os.cmd('echo "" >> #{file}')
        :os.cmd('echo "  alias #{module_name}Web.FallbackController" >> #{file}')
        :os.cmd('echo "" >> #{file}')
        :os.cmd('echo "  alias Plug.Conn" >> #{file}')
        :os.cmd('echo "" >> #{file}')
        :os.cmd('echo "  def handle(conn, data) do" >> #{file}')
        :os.cmd('echo "    try do" >> #{file}')

        v2 = Enum.reduce(vars, "", fn ({wh, cur}, acc) ->
          acc <> (
            case wh do
              :optional_param ->
                "      #{cur} = data[\\\"#{cur}\\\"]\n\n"
              :param ->
                "      #{cur} = data[\\\"#{cur}\\\"]\n\n"
             <> "      if #{cur} === nil do\n"
             <> "        raise \\\"miss #{cur}\\\"\n"
             <> "      end\n\n"
              :conn ->
                "      #{cur} = conn.#{cur}\n\n"
              :header ->
                "      #{cur} = Conn.get_req_header(conn, \\\"#{String.replace(cur, "_", "-")}\\\")\n\n"
             <> "      #{cur} = case #{cur} do\n"
             <> "        [fst | _] ->\n"
             <> "          fst\n"
             <> "        [] ->\n"
             <> "          nil\n"
             <> "      end\n\n"
            end
          )
        end)
        |> String.trim()

        :os.cmd('echo "      #{v2}" >> #{file}')
        :os.cmd('echo "" >> #{file}')
        :os.cmd('echo "      result = #{String.upcase(method)}_#{String.upcase(p)}.run!(#{v})" >> #{file}')
        :os.cmd('echo "" >> #{file}')
        :os.cmd('echo "      conn" >> #{file}')
        :os.cmd('echo "      |> put_status(:ok)" >> #{file}')
        :os.cmd('echo "      |> json(result)" >> #{file}')
        :os.cmd('echo "    rescue err ->" >> #{file}')
        :os.cmd('echo "      IO.inspect(__STACKTRACE__)" >> #{file}')
        :os.cmd('echo "      FallbackController.call(conn, {:error, err})" >> #{file}')
        :os.cmd('echo "    end" >> #{file}')
        :os.cmd('echo "  end" >> #{file}')
        :os.cmd('echo "end" >> #{file}')

        # TODO LO_SEVERITY allow root path '/api/'
        call = "10i\\\n\\\n\\    #{method} \\\"/#{path}\\\", #{String.upcase(method)}_#{String.upcase(p)}Controller, :handle"
        System.cmd("sed", ["-i", call, "#{dir_name}/lib/#{app_name}_web/router.ex"])
      _ ->
        raise "ERROR #{file_name}:#{num} invalid format"
    end
  end

  # no longer maintained
  defp parse_create(str, schema, transact, module_name, file_name, num, agent) do
    # TODO transaction and transaction early ending

    lines = str
            |> String.split("\n")

    {fields, vars, blocks, _} = lines
                                |> Enum.with_index(
    )
    |> Enum.reduce({[], [], [], nil}, fn ({cur, i}, {fields, vars, blocks, extend}) ->
      if extend do
        {headers, body, i} = extend

        if cur == "" do
          {inc, var, new_blocks} = parse_create_field(headers, body, module_name, file_name, i, agent)

          {(if inc, do: [hd(headers) | fields], else: fields), (if var, do: [var | vars], else: vars), new_blocks ++ blocks, nil}
        else
          cur = cur
                |> to_charlist
                |> tl |> tl
                |> to_string

          {fields, vars, blocks, {headers, body <> cur <> "\n", i}}
        end
      else
        if cur != "" do
          tokens = cur
                   |> String.split(" ", trim: true)

          if length(tokens) <= 2 do
            {inc, var, new_blocks} = parse_create_field(tokens, nil, module_name, file_name, num + i, agent)

            {(if inc, do: [hd(tokens) | fields], else: fields), (if var, do: [var | vars], else: vars), new_blocks ++ blocks, nil}
          else
            {fields, vars, blocks, {tokens, "", num + i}}
          end
        else
          {fields, vars, blocks, extend}
        end
      end
    end)

    fields = fields
             |> Enum.reverse()

    insert = if transact do
      "{:ok, result} = Repo.transaction(fn ->\n\n"
    else
      ""
    end

    insert = insert <> "created = %#{String.upcase(schema)} {\n"

    insert = Enum.reduce(fields, insert, fn (cur, acc) ->
      acc <> "  #{cur}: #{cur},\n"
    end)

    insert = insert <> "}\n"

    insert = insert <> "|> Repo.insert!\n\n"

    insert = insert <> "%{id: created.id}"

    {vars, [insert | blocks]}
  end

  # no longer maintained
  defp parse_create_field(headers, body, module_name, file_name, num, agent) do
    [field, dec | _] = headers

    field = field
            |> apply_shortcuts(agent)

    {inc, var, blocks} = case dec do
      "+" ->
        {false, {:conn, field}, []}
      "^" ->
        {false, {:header, field}, []}
      "|" ->
        {false, nil, []}
      "*" ->
        {false, {:param, field}, []}
      "()" ->
        {true, {:param, field}, []}
      "(" <> var ->
        rev = var
              |> String.reverse()

        case rev do
          ")" <> var ->
            var = var
                  |> String.reverse()

            {true, {:param, var}, ["#{field} = #{var}"]}
          var ->
            var = var
                  |> String.reverse()

            {true, {:param, var}, ["#{field} = #{var}"]}
        end
      "`" <> exec ->
        rev = exec
              |> String.reverse()

        case rev do
          "`" <> exec ->
            exec = exec
                   |> String.reverse()

            {true, nil, ["#{field} = #{exec}"]}
          exec ->
            exec = exec
                   |> String.reverse()

            {true, nil, ["#{field} = #{exec}"]}
        end
    end

    blocks = if body do
      parse_field_body(body, field, module_name, file_name, num, agent) ++ blocks
    else
      blocks
    end

    {inc, var, blocks}
  end

  defp parse_validate(str, trail, module_name, file_name, num, agent) do
    lines = str
            |> String.split("\n")

    {blocks, indent} = case trail do
      "Tr" ->
        {["    Repo.query!(\"set transaction isolation level repeatable read\")\n", "  {:ok, result} = Repo.transaction(fn ->", "try do"], "    "}
      "tr" ->
        {["  {:ok, result} = Repo.transaction(fn ->", "try do"], "    "}
      "T" ->
        {["  Repo.query!(\"set transaction isolation level repeatable read\")\n", "{:ok, result} = Repo.transaction(fn ->"], "  "}
      "t" ->
        {["{:ok, result} = Repo.transaction(fn ->"], "  "}
      "r" ->
        {["try do"], "  "}
      "" ->
        {[], ""}
    end

    {vars, blocks, _} = lines
                        |> Enum.with_index(
    )
    |> Enum.reduce({[], blocks, nil}, fn ({cur, i}, {vars, blocks, extend}) ->
      if extend do
        {headers, body, i} = extend

        if cur == "" do
          {var, new_blocks} = parse_validate_field(headers, body, module_name, file_name, i, agent)

          new_blocks = Enum.map(new_blocks, fn (cur) ->
            indent <> cur
          end)

          {[var | vars], new_blocks ++ blocks, nil}
        else
          cur = cur
                |> to_charlist
                |> tl |> tl
                |> to_string

          {vars, blocks, {headers, body <> cur <> "\n", i}}
        end
      else
        if cur != "" do
          tokens = cur
                   |> String.split(" ", trim: true)

          if length(tokens) <= 1 do
            {var, new_blocks} = parse_validate_field(tokens, nil, module_name, file_name, num + i, agent)

            {[var | vars], new_blocks ++ blocks, nil}
          else
            {vars, blocks, {tokens, "", num + i}}
          end
        else
          {vars, blocks, extend}
        end
      end
    end)

    blocks = [indent <> "###\n" | blocks]

    {vars, blocks}
  end

  defp parse_validate_field(headers, body, module_name, file_name, num, agent) do
    [field | _] = headers

    field = field
            |> apply_shortcuts(agent)

    var = case field do
      "+" <> var ->
        {:conn, var}
      "^" <> var ->
        {:header, var}
      "|" <> var ->
        {:noop, var}
      "*" <> var ->
        {:optional_param, var}
      var ->
        {:param, var}
    end

    {_, field} = var

    blocks = if body do
      parse_field_body(body, field, module_name, file_name, num, agent)
    else
      []
    end

    {var, blocks}
  end

  # this one is not escaped from raw bash because in `` and using file
  defp parse_field_body(str, field, module_name, file_name, num, agent) do
    lines = str
            |> String.split("\n")

    lines
    |> Enum.with_index()
    |> Enum.reduce([], fn ({cur, i}, acc) ->
      if cur != "" do
        tokens = cur
                 |> String.split(" ", trim: true)

        [action, type | extra] = tokens

        new = case action do
          "v" ->
            case type do
              "empty" ->
                rs = case extra do
                  [msg] ->
                    msg
                    |> apply_shortcuts(agent)
                    |> String.replace("&cur", field)
                  [] ->
                    "#{type} #{field}"
                end

                [
                  "if #{field} == \"\" || #{field} == '' do",
                  "  raise \"#{rs}\"",
                  "end\n"
                ]
              "min-len" ->
                [len | extra] = extra

                rs = case extra do
                  [msg] ->
                    msg
                    |> apply_shortcuts(agent)
                    |> String.replace("&cur", field)
                  [] ->
                    "#{type} #{len} #{field}"
                end

                [
                  "if String.valid?(#{field}) do",
                  "  if String.length(#{field}) < #{len} do",
                  "    raise \"#{rs}\"",
                  "  end",
                  "else",
                  "  if length(#{field}) < #{len} do",
                  "    raise \"#{rs}\"",
                  "  end",
                  "end\n"
                ]
              # TODO do these
              "max-len" ->
                [len] = extra

                [
                  "if String.valid?(#{field}) do",
                  "  if String.length(#{field}) > #{len} do",
                  "    raise \"#{type} #{len} #{field}\"",
                  "  end",
                  "else",
                  "  if length(#{field}) > #{len} do",
                  "    raise \"#{type} #{len} #{field}\"",
                  "  end",
                  "end\n"
                ]
              "length" ->
                [min, max] = extra

                [
                  "if String.valid?(#{field}) do",
                  "  if String.length(#{field}) < #{min} || String.length(#{field}) > #{max} do",
                  "    raise \"#{type} #{min} #{max} #{field}\"",
                  "  end",
                  "else",
                  "  if length(#{field}) < #{min} || length(#{field}) > #{max} do",
                  "    raise \"#{type} #{min} #{max} #{field}\"",
                  "  end",
                  "end\n"
                ]
              "regex" ->
                [regex] = extra

                [
                  "if !String.match?(#{field}, #{regex}) do",
                  "  raise \"#{type} #{regex} #{field}\"",
                  "end\n"
                ]
              "`" <> c ->
                c = c
                    |> String.reverse()

                "`" <> c = c

                c = c
                    |> String.reverse()
                    |> apply_shortcuts(agent)
                    |> String.replace("&cur", field)

                [p] = extra

                p = p
                    |> apply_shortcuts(agent)
                    |> String.replace("&cur", field)

                [
                  "if #{c} do",
                  "  raise \"#{p}\"",
                  "end\n",
                ]
              _ ->
                raise "# not imp'd"
            end
          "t" ->
            case type do
              "~" <> n ->
                n = if n == "" do
                  field
                else
                  n
                end

                ["#{field} =" |
                 n
                 |> get_snippet(agent)
                 |> Enum.map(fn (cur) ->
                   cur
                   |> apply_shortcuts(agent)
                   |> String.replace("&cur", field)
                 end)
                ]
              "`" <> c ->
                c = c
                    |> String.reverse()

                "`" <> c = c

                c = c
                    |> String.reverse()
                    |> apply_shortcuts(agent)
                    |> String.replace("&cur", field)

                ["#{field} = #{c}\n"]
              _ ->
                raise "# tnot imp'd"
            end
          "tt" ->
            tvar = type
                   |> apply_shortcuts(agent)
                   |> String.replace("&cur", field)

            [type] = extra

            type = type
                   |> apply_shortcuts(agent)
                   |> String.replace("&cur", field)

            case type do
              "~" <> n ->
                n = if n == "" do
                  tvar
                else
                  n
                end

                ["#{tvar} =" |
                  n
                  |> get_snippet(agent)
                  |> Enum.map(fn (cur) ->
                    cur
                    |> apply_shortcuts(agent)
                    |> String.replace("&cur", field)
                    |> String.replace("&var", tvar)
                  end)
                ]
              "`" <> c ->
                c = c
                    |> String.reverse()

                "`" <> c = c

                c = c
                    |> String.reverse()
                    |> apply_shortcuts(agent)
                    |> String.replace("&cur", field)
                    |> String.replace("&var", tvar)

                ["#{tvar} = #{c}\n"]
              _ ->
                raise "# ttnot imp'd"
            end
        end
        |> Enum.reverse()

        new ++ acc
      else
        acc
      end
    end)
  end

  # FIXME shortcut applying is all over the place, slowing parser down
  defp apply_multiline(str, agent) do
    # TODO shortcuts stored as &name => <shortcut> but snippets stored as name => <snippet>
    # (no &~ for snippet!)
    str
    |> String.split("\n")
    |> Enum.map(&(String.split(&1, "&+")))
    |> Enum.map(fn cur ->
      case cur do
        [indent, name] ->
          snip_lines = get_snippet(name, agent)

          if snip_lines do
            snip_lines
            |> Enum.map(fn cur ->
              indent <> cur
            end)
          else
            cur
          end
        _ ->
          cur
      end
    end)
    |> List.flatten()
    |> Enum.reduce("", fn cur, acc -> acc <> cur <> "\n" end)
  end

  defp apply_shortcuts(str, agent) do
    agent
    |> Agent.get(fn (cur) ->
      cur.shortcuts
    end, :infinity)
    |> Enum.reduce(str, fn ({this, that}, acc) ->
      acc
      |> String.replace(this, that)
    end)
  end

  # TODO preload all snippets to make faster
  defp get_snippet(name, agent) do
    agent
    |> Agent.get(fn (cur) ->
      cur.snippets[name]
    end, :infinity)
  end
end
