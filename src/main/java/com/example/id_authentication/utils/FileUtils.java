package com.example.id_authentication.utils;

import org.springframework.stereotype.Component;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Component
public class FileUtils {
    public static String getCanonicalPath () throws IOException
    {
        return new File (".").getCanonicalPath ();
    }

    public String getFilePath(String fileName) {
        try {
            String canonicalPath = getCanonicalPath();
            Path filePath = Paths.get(canonicalPath, fileName);

            if (Files.exists(filePath)) {
                return filePath.toAbsolutePath().toString();
            } else {
                throw new FileNotFoundException("File not found: " + fileName + " in directory: " + canonicalPath);
            }
        } catch (Exception e) {
            throw new RuntimeException("Error getting file path: " + fileName, e);
        }
    }
}