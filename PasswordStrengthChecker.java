import java.util.HashSet;
import java.util.Set;
import java.util.Scanner;

public class PasswordStrengthChecker {
    private static final Set<String> COMMON_PASSWORDS = new HashSet<>();

    static {
        String[] common = {
            "password", "password123", "123456", "123456789",
            "12345678", "qwerty", "qwerty123", "admin",
            "letmein", "welcome", "iloveyou", "abc123",
            "111111", "123123", "india123"
        };
        for (String p : common) {
            COMMON_PASSWORDS.add(p);
        }
    }

    private static double calculateEntropy(String password) {
        int pool = 0;

        if (password.matches("(?s).*\\p{Lower}.*")) pool += 26;
        if (password.matches("(?s).*\\p{Upper}.*")) pool += 26;
        if (password.matches("(?s).*\\d.*")) pool += 10;
        if (password.matches("(?s).*[^a-zA-Z0-9\\s].*")) pool += 32;
        if (password.matches("(?s).*\\s.*")) pool += 1;

        if (password.isEmpty() || pool == 0) return 0.0;
        return password.length() * (Math.log(pool) / Math.log(2));
    }

    private static boolean hasUppercase(String password) {
        return password.matches("(?s).*\\p{Upper}.*");
    }

    private static boolean hasLowercase(String password) {
        return password.matches("(?s).*\\p{Lower}.*");
    }

    private static boolean hasDigit(String password) {
        return password.matches("(?s).*\\d.*");
    }

    private static boolean hasSpecialCharacter(String password) {
        return password.matches("(?s).*[^a-zA-Z0-9\\s].*");
    }

    private static void printCheck(String label, boolean passed) {
        System.out.println("[" + (passed ? "PASS" : "FAIL") + "] " + label);
    }

    private static String classifyStrength(String password, double entropy,
                                           int passedChecks, boolean commonPassword) {
        if (commonPassword || password.length() < 8) {
            return "Weak";
        }
        if (entropy < 50 || passedChecks < 4) {
            return "Moderate";
        }
        if (entropy < 75 || passedChecks < 5) {
            return "Strong";
        }
        return "Exceptional";
    }

    private static void printSuggestions(String password, boolean commonPassword) {
        boolean anySuggestion = false;

        if (password.length() < 12) {
            System.out.println("- Use at least 12 characters; a longer passphrase is even better.");
            anySuggestion = true;
        }
        if (!hasUppercase(password)) {
            System.out.println("- Add an uppercase letter (A-Z).");
            anySuggestion = true;
        }
        if (!hasLowercase(password)) {
            System.out.println("- Add a lowercase letter (a-z).");
            anySuggestion = true;
        }
        if (!hasDigit(password)) {
            System.out.println("- Consider adding a digit (0-9).");
            anySuggestion = true;
        }
        if (!hasSpecialCharacter(password)) {
            System.out.println("- Consider adding a symbol such as !, @, #, or %.");
            anySuggestion = true;
        }
        if (!password.equals(password.trim())) {
            System.out.println("- Remove spaces at the beginning or end.");
            anySuggestion = true;
        }
        if (commonPassword) {
            System.out.println("- This is in the small built-in common-password list. Choose a unique password.");
            anySuggestion = true;
        }
        if (!anySuggestion) {
            System.out.println("- Good basic policy result. Use a unique password and enable multi-factor authentication.");
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("================================================");
        System.out.println("          PASSWORD STRENGTH CHECKER");
        System.out.println("================================================");
        System.out.print("Enter a test password: ");
        String password = scanner.nextLine();

        boolean lengthOk = password.length() >= 12;
        boolean upperOk = hasUppercase(password);
        boolean lowerOk = hasLowercase(password);
        boolean digitOk = hasDigit(password);
        boolean specialOk = hasSpecialCharacter(password);
        boolean whitespaceOk = password.equals(password.trim());

        int passedChecks = 0;
        if (lengthOk) passedChecks++;
        if (upperOk) passedChecks++;
        if (lowerOk) passedChecks++;
        if (digitOk) passedChecks++;
        if (specialOk) passedChecks++;
        if (whitespaceOk) passedChecks++;

        boolean commonPassword = COMMON_PASSWORDS.contains(password.toLowerCase());
        double entropy = calculateEntropy(password);
        String strength = classifyStrength(password, entropy, passedChecks, commonPassword);

        System.out.println("\n--- POLICY CHECKS ---");
        printCheck("At least 12 characters", lengthOk);
        printCheck("Contains uppercase letter", upperOk);
        printCheck("Contains lowercase letter", lowerOk);
        printCheck("Contains a digit", digitOk);
        printCheck("Contains a special character", specialOk);
        printCheck("No leading/trailing whitespace", whitespaceOk);

        System.out.println("\n--- ANALYSIS ---");
        System.out.println("Password length        : " + password.length() + " characters");
        System.out.printf("Estimated entropy      : %.2f bits%n", entropy);
        System.out.println("Common-password check  : " +
                (commonPassword ? "MATCH FOUND" : "No match in small built-in list"));
        System.out.println("Strength classification: " + strength);

        System.out.println("\n--- SUGGESTIONS ---");
        printSuggestions(password, commonPassword);

        System.out.println("\nSecurity note: This program does not save or send the password.");
        System.out.println("The common-password list is small; this is not a live breach database.");
        scanner.close();
    }
}
