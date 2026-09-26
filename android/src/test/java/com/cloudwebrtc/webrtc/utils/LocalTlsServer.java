package com.cloudwebrtc.webrtc.utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * A real TLS server on loopback, and the throwaway authority behind it.
 *
 * <p>Chain learning is a network operation, so the only honest way to test it is to let it
 * happen. Two shapes are needed: one that completes a handshake, and one that accepts a
 * connection and then says nothing, which is what a stalled server looks like from outside.
 *
 * <p>Everything is generated when the tests run, with the `keytool` of the JDK already running
 * them: an authority, a leaf it signs for `localhost`, and a key store holding both. Nothing is
 * committed, so there is no private key in the tree for a secret scanner to stop on and no
 * fixture to regenerate when one expires.
 */
final class LocalTlsServer implements AutoCloseable {
  private static final String PASSWORD = "changeit";

  private static File keyStore;
  private static X509Certificate authority;

  private final ServerSocket socket;
  private final Thread thread;
  private final java.util.concurrent.atomic.AtomicReference<Socket> active;
  private final java.util.concurrent.atomic.AtomicInteger accepted;

  private LocalTlsServer(ServerSocket socket,
                         java.util.concurrent.atomic.AtomicInteger accepted,
                         Thread thread,
                         java.util.concurrent.atomic.AtomicReference<Socket> active) {
    this.socket = socket;
    this.accepted = accepted;
    this.thread = thread;
    this.active = active;
  }

  /**
   * How many connections this server has accepted.
   *
   * <p>"Was the server contacted at all" is a different question from "how long did it take",
   * and the cache tests turn on the first one: a caller handed a cached empty result never
   * reaches the server, and the elapsed time looks perfect.
   */
  int connections() {
    return accepted.get();
  }

  /** The generated authority - what a client has to trust to accept this server. */
  static synchronized X509Certificate authority() throws Exception {
    generate();
    return authority;
  }

  /** An {@link SSLContext} trusting that authority and nothing else. */
  static SSLContext trustingTheAuthority() throws Exception {
    KeyStore roots = KeyStore.getInstance(KeyStore.getDefaultType());
    roots.load(null, null);
    roots.setCertificateEntry("authority", authority());

    TrustManagerFactory trust =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trust.init(roots);

    SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, trust.getTrustManagers(), null);
    return context;
  }

  /** Completes handshakes, presenting the generated leaf and the authority above it. */
  static LocalTlsServer answering() throws Exception {
    return answering(0);
  }

  /** Delays only the first handshake, allowing a timed-out client to retry successfully. */
  static LocalTlsServer answering(final long firstDelayMs) throws Exception {
    generate();

    KeyStore keys = KeyStore.getInstance("PKCS12");
    try (FileInputStream in = new FileInputStream(keyStore)) {
      keys.load(in, PASSWORD.toCharArray());
    }

    KeyManagerFactory keyManagers =
            KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagers.init(keys, PASSWORD.toCharArray());

    SSLContext context = SSLContext.getInstance("TLS");
    context.init(keyManagers.getKeyManagers(), null, null);

    final SSLServerSocket server = (SSLServerSocket) context.getServerSocketFactory()
            .createServerSocket(0, 4, InetAddress.getByName("127.0.0.1"));

    final java.util.concurrent.atomic.AtomicInteger counted =
            new java.util.concurrent.atomic.AtomicInteger();
    final java.util.concurrent.atomic.AtomicReference<Socket> active =
            new java.util.concurrent.atomic.AtomicReference<>();
    return new LocalTlsServer(server, counted, started(new Runnable() {
      @Override
      public void run() {
        while (!server.isClosed()) {
          try (Socket client = server.accept()) {
            active.set(client);
            if (server.isClosed()) return;
            if (counted.incrementAndGet() == 1 && firstDelayMs > 0) {
              Thread.sleep(firstDelayMs);
            }
            // One read is enough to drive the handshake to completion.
            client.getInputStream().read();
          } catch (Exception stop) {
            if (server.isClosed() || stop instanceof InterruptedException) return;
          } finally {
            active.set(null);
          }
        }
      }
    }), active);
  }

  /** Accepts and then holds the connection without speaking TLS, for as long as it is told. */
  static LocalTlsServer stalling(final long holdMs) throws Exception {
    final ServerSocket server = new ServerSocket(0, 4, InetAddress.getByName("127.0.0.1"));
    final java.util.concurrent.atomic.AtomicInteger counted =
            new java.util.concurrent.atomic.AtomicInteger();
    final java.util.concurrent.atomic.AtomicReference<Socket> active =
            new java.util.concurrent.atomic.AtomicReference<>();
    return new LocalTlsServer(server, counted, started(new Runnable() {
      @Override
      public void run() {
        while (!server.isClosed()) {
          try (Socket client = server.accept()) {
            active.set(client);
            if (server.isClosed()) return;
            counted.incrementAndGet();
            Thread.sleep(holdMs);
          } catch (Exception stop) {
            if (server.isClosed() || stop instanceof InterruptedException) return;
          } finally {
            active.set(null);
          }
        }
      }
    }), active);
  }

  /** `host:port` in the shape {@link TurnServerChains#endpointOf} produces. */
  String endpoint() {
    return "localhost:" + socket.getLocalPort();
  }

  @Override
  public void close() throws Exception {
    socket.close();
    Socket client = active.get();
    if (client != null) client.close();
    thread.interrupt();
    thread.join(1000);
  }

  private static void generate() throws Exception {
    if (keyStore != null) {
      return;
    }
    File directory = Files.createTempDirectory("flutter-webrtc-tls").toFile();
    directory.deleteOnExit();
    File store = new File(directory, "server.p12");
    File request = new File(directory, "leaf.csr");
    File signed = new File(directory, "leaf.pem");

    keytool(store, "-genkeypair", "-alias", "authority",
            "-dname", "CN=flutter-webrtc test authority",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "1", "-ext", "bc:c");
    keytool(store, "-genkeypair", "-alias", "server", "-dname", "CN=localhost",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "1");
    keytool(store, "-certreq", "-alias", "server", "-file", request.getPath());
    // Signed by the authority, so leaf and authority are a chain the platform can walk.
    keytool(store, "-gencert", "-alias", "authority", "-infile", request.getPath(),
            "-outfile", signed.getPath(), "-validity", "1",
            "-ext", "san=dns:localhost,ip:127.0.0.1", "-rfc");
    // The signed leaf goes back in under its own alias; keytool finds the issuer beside it and
    // stores the pair as one chain, which is what the server then presents.
    keytool(store, "-importcert", "-alias", "server", "-file", signed.getPath(), "-noprompt");

    for (File each : new File[] {store, request, signed}) {
      each.deleteOnExit();
    }

    KeyStore loaded = KeyStore.getInstance("PKCS12");
    try (FileInputStream in = new FileInputStream(store)) {
      loaded.load(in, PASSWORD.toCharArray());
    }
    authority = (X509Certificate) loaded.getCertificate("authority");
    keyStore = store;
  }

  private static void keytool(File store, String... arguments) throws Exception {
    List<String> command = new ArrayList<>();
    command.add(System.getProperty("java.home") + File.separator + "bin"
            + File.separator + "keytool");
    command.addAll(Arrays.asList(arguments));
    command.addAll(Arrays.asList("-keystore", store.getPath(), "-storetype", "PKCS12",
            "-storepass", PASSWORD, "-keypass", PASSWORD));

    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buffer = new byte[4096];
    int read;
    while ((read = process.getInputStream().read(buffer)) > 0) {
      out.write(buffer, 0, read);
    }
    if (process.waitFor() != 0) {
      throw new IllegalStateException(
              "keytool " + arguments[1] + " failed: " + out.toString("UTF-8"));
    }
  }

  private static Thread started(Runnable body) {
    Thread thread = new Thread(body);
    thread.setDaemon(true);
    thread.start();
    return thread;
  }
}
