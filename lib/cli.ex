defmodule Worm.CLI do
  def main(args) do
    options = [
      switches: [dir_name: :string, app_name: :string, module_name: :string],
      aliases: [d: :dir_name, a: :app_name, m: :module_name]
    ]

    {[dir_name: dir_name, app_name: app_name, module_name: module_name], files} = OptionParser.parse!(args, options)

    Worm.init(dir_name, app_name, module_name)

    {:ok, agent} = Agent.start_link(fn -> %{
      mig_idx: 0,
      shortcuts: [
        {"&usec", "utc_datetime_usec"},
        {"&sec", "utc_datetime"},
        {"&bid", "binary_id"},
        {"&m", module_name},
        {"&app", app_name},
        {"&dir", dir_name},
        {"&>", "\t"},
        {"&;", "\n"},
        {"&_", " "},
      ],
      snippets: %{}
    } end)

    files = files
            |> Enum.uniq()

    try do
      Enum.each(files, fn (cur) ->
        IO.puts(IO.ANSI.bright() <> "WORM parsing #{cur}" <> IO.ANSI.reset())

        if !String.contains?(cur, ".") do
          raise "ERROR #{cur} unsupported file extension <no file extension>"
        end

        ext = cur
              |> String.split(".", trim: true)
              |> Enum.reverse()
              |> hd

        case ext do
          "worm" ->
            Worm.parse(cur, dir_name, app_name, module_name, agent)
          "wormcm" ->
            Worm.parse_custom(cur, dir_name, app_name, module_name, agent)
          "wormenv" ->
            System.cmd("cp", [cur, "#{dir_name}/.env"])
          _ ->
            raise "ERROR #{cur} unsupported file extension '#{ext}'"
        end
      end)

      System.cmd("rm", ["-r", "#{dir_name}/_build/dev/lib/#{app_name}"])
    rescue err ->
      IO.inspect err

      __STACKTRACE__
      |> Exception.format_stacktrace()
      |> IO.write

      System.cmd("rm", ["-r", "#{dir_name}.err"])
      System.cmd("mv", [dir_name, "#{dir_name}.err"])
      System.cmd("mv", ["#{dir_name}.bak", dir_name])
    end
  end
end
