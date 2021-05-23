package de.hpi.ddm.structures;

import lombok.*;

import java.util.List;
import java.util.Queue;

@Data
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class PasswordEntry {
    private int id;
    private String name;
    private String passwordChars;
    private int passwordLength;
    private String hashedPassword;
    private String plainPassword;
    private Queue<String> hashedHints;
    private List<String> hints;

}
