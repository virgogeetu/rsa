package rsa;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.xml.bind.DatatypeConverter;

public class RsaFileUtil {

	// writes data to a file
	public static final void writeToFile(final String filepath, final String data) {
		writeToFile(filepath, data.getBytes());
	}

	// write data converted to bytes to file in hex format
	public static final void writeFileHexFormat(final String filepath, final byte[] data) {
		writeToFile(filepath, DatatypeConverter.printHexBinary(data));
	}

	// write data converted to bytes to file
	public static final void writeToFile(final String filepath, final byte[] data) {
		try (final FileOutputStream outputStream = new FileOutputStream(filepath)) {
			outputStream.write(data);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// read data from file
	public static final byte[] readFromFile(final String filepath) {
		try (final BufferedReader reader = Files.newBufferedReader(Paths.get(filepath), StandardCharsets.UTF_8)) {
			final StringBuilder sb = new StringBuilder();
			String line;
			while ((line = reader.readLine()) != null) {
				sb.append(line);
			}
			return DatatypeConverter.parseHexBinary(sb.toString());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}
