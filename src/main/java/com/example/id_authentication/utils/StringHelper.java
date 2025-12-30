package com.example.id_authentication.utils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class StringHelper {

    public static String base64UrlEncode (byte [] arg)
    {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(arg);
    }

    public static String base64UrlEncode (String arg)
    {
        byte[] utf8Bytes = arg.getBytes(StandardCharsets.UTF_8);
        return base64UrlEncode(utf8Bytes);
    }

    public static byte[] base64UrlDecode (String arg)
    {
        int padding = 4 - (arg.length() % 4);
        if (padding < 4) {
            arg += "=".repeat(padding);
        }

        return Base64.getUrlDecoder().decode(arg);
    }

    public static byte [] toUtf8ByteArray (String arg)
    {
        return arg.getBytes (StandardCharsets.UTF_8);
    }

    public static boolean isValidLength(String value, int minLength, int maxLength) {
        if(value == null) {
            return false;
        }

        int length = value.length();
        return length >= minLength && length <= maxLength;
    }

    public static boolean isAlphaNumericHyphenWithMinMaxLength(String input) {
        if(input == null) {
            return false;
        }
        // Regular expression for Match alphanumeric characters or hyphens, with no whitespaces and with a length between minLength and maxLength
        String regex = "^[a-zA-Z0-9-]{4,50}$";

        // Check if the input string matches the pattern
        return input.matches(regex);
    }
}