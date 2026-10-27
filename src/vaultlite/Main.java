package vaultlite;

public final class Main {
    public static void main(String[] args) {
        int code = new Cli(System.in, System.out, System.err).run(args);
        if (code != 0) System.exit(code);
    }
}
