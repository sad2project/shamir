// Implementation of join() was altered by Jacob Zimmerman to put in a check that enough parts were received


/*
 * Copyright © 2017 Coda Hale (coda.hale@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.shamir;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;

import com.shamir.BytesBuilder;

/**
 * An implementation of Shamir's Secret Sharing over {@code GF(256)} to securely split secrets into
 * {@code N} parts, of which any {@code K} can be joined to recover the original secret.
 *
 * <p>{@link Scheme} uses the same GF(256) field polynomial as the Advanced Encryption Standard
 * (AES): {@code 0x11b}, or {@code x}<sup>8</sup> + {@code x}<sup>4</sup> + {@code x}<sup>3</sup> +
 * {@code x} + 1.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing">Shamir's Secret
 *     Sharing</a>
 * @see <a href="http://www.cs.utsa.edu/~wagner/laws/FFM.html">The Finite Field {@code GF(256)}</a>
 */
public class Scheme {

  private final SecureRandom random;
  private final int partsCount;
  private final int threshold;

  /**
   * Creates a new {@link Scheme} instance.
   *
   * @param random a {@link SecureRandom} instance
   * @param n the number of parts to produce (must be {@code >1})
   * @param k the threshold of joinable parts (must be {@code <= n})
   */
  public Scheme(SecureRandom random, int n, int k) {
    this.random = random;
    checkArgument(k > 1, "Must have more than 1 part");
    checkArgument(n >= k, "Threshold must be <= the number of parts");
    checkArgument(n <= 255, "Threshold must be <= 255");
    this.partsCount = n;
    this.threshold = k;
  }

  /**
   * Splits the given secret into {@code n} parts, of which any {@code k} or more can be combined to
   * recover the original secret.
   *
   * @param secret the secret to split
   * @return a map of {@code n} part IDs and their values
   */
  public Map<Integer, byte[]> split(byte[] secret) {

    final BytesBuilder values = BytesBuilder.autoIndexSecond(partsCount, secret.length);
    
    for (int i = 0; i < secret.length; i++) {
      values.add(calcPartsForSecretByte(secret[i], partsCount));
    }

    return createPartsMap(values.toBytes());
  }

  /**
   * Creates a specific byte for each part from the given byte from the secret
   * @param secretByte byte from the secret to split into parts
   * @param partsCount number of parts to split the secret into
   * @return byte array with a byte for each part
   */
  private byte[] calcPartsForSecretByte(byte secretByte, int partsCount) {
    // for each byte, generate a random polynomial
    final byte[] poly = GF256.generate(random, threshold - 1, secretByte);
    final byte[] parts = new byte[partsCount];

    for (int part = 1; part <= partsCount; part++) {
      parts[part-1] = GF256.eval(poly, (byte) part);
    }

    return parts;
  }

  /**
   * Converts the array of parts values into a Map of part #s to byte array values
   * for that part
   * @param values 2D byte array where the first index is for the part number and it
   * points to a byte array value
   * @return Map from part #s to their corresponding byte arrays
   */
  private Map<Integer, byte[]> createPartsMap(byte[][] values) {
    final Map<Integer, byte[]> parts = new HashMap<>(values.length);
    for (int part = 0; part < values.length; part++) {
      parts.put(part + 1, values[part]);
    }
    return Collections.unmodifiableMap(parts);
  }

  /**
   * Joins the given parts to recover the original secret.
   *
   * <p><b>N.B.:</b> There is no way to determine whether or not the returned value is actually the
   * original secret. If the parts are incorrect, a random value will be returned.
   *
   * @param parts a map of part IDs to part values
   * @return the original secret
   * @throws IllegalArgumentException if {@code parts} is empty, contains too few parts, or contains 
   *     values of varying lengths
   */
  public byte[] join(Map<Integer, byte[]> parts) {
    checkArgument(parts.size() > 0, "No parts provided");
    checkArgument(parts.size() >= k, "Not enough parts provided");
    final int length = lengthOfArraysIn(parts.values());

    final byte[] secret = new byte[length];
    for (int i = 0; i < length; i++) {
      secret[i] = calcSecretByte(i, parts);
    }
    return secret;
  }

  /**
   * Calculates the length of the byte arrays and ensures that they're all the same length
   * @param bytesSet iterable of byte arrays to look up the length of the arrays in
   * @return length of the byte arrays
   * @throws IllegalArgumentException if the lengths of each of the byte arrays aren't the same
   */
  private int lengthOfArraysIn(Iterable<byte[]> bytesSet) {
    int[] lengths = bytesSet.stream().mapToInt(bts -> bts.length).distinct().toArray();
    checkArgument(lengths.length == 1, "Varying lengths of part values");
    return lengths[0];
  }

  /**
   * Calculates the secret byte based on the corresponding byte for each part
   * @param byteNumber 
   * @param parts
   * @return
   */
  private byte calcSecretByte(int byteNumber, Map<Integer, byte[]> parts) {
    final BytesBuilder points = BytesBuilder.autoIndexFirst(parts.size(), 2);

    // gets the part number and part value for the given byte
    for (Map.Entry<Integer, byte[]> part : parts.entrySet()) {
      points.add(part.getKey().byteValue(), part.getValue()[byteNumber]);
    }
    return GF256.interpolate(points.toBytes());
  }

  /**
   * The number of parts the scheme will generate when splitting a secret.
   *
   * @return {@code partsCount}
   */
  public int n() { return partsCount; }
  public int partsCount() { return partsCount; }

  /**
   * The number of parts the scheme will require to re-create a secret.
   *
   * @return {@code threshold}
   */
  public int k() { return threshold; }
  public int threshold() { return threshold; }

  @Override
  public boolean equals(Object o) {
    if (this == o) { return true; }
    if (!(o instanceof Scheme)) { return false; }

    final Scheme scheme = (Scheme) o;
    return partsCount == scheme.partsCount && 
        threshold == scheme.threshold && 
        Objects.equals(random, scheme.random);
  }

  @Override
  public int hashCode() {
    return Objects.hash(random, n, k);
  }

  @Override
  public String toString() {
    return new StringJoiner(", ", Scheme.class.getSimpleName() + "[", "]")
        .add("random=" + random)
        .add("partsCount=" + partsCount)
        .add("threshold=" + threshold)
        .toString();
  }

  /**
   * If the given condition is false, an IllegalArgumentException with the given message is thrown
   * @param condition condition to determine if the argument is okay
   * @param message message to put in the possible IllegalArgumentException
   */
  private static void checkArgument(boolean condition, String message) {
    if (!condition) {
      throw new IllegalArgumentException(message);
    }
  }
}
