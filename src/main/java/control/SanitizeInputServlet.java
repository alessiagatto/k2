package control;

import com.google.common.html.HtmlEscapers;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Pattern;

/**
 * Servlet implementation class SanitizeInputServlet
 */
@WebServlet("/sanitizeInput")
public class SanitizeInputServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    // Policy di sanificazione
    private static final PolicyFactory POLICY = Sanitizers.FORMATTING.and(Sanitizers.LINKS);

    // Pattern per validare l'input e prevenire XSS
    private static final Pattern INVALID_CHARACTERS = Pattern.compile("[<>\"'/]");

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // Ottieni l'input dall'utente
        String userInput = request.getParameter("userInput");

        // Valida l'input
        if (userInput == null || INVALID_CHARACTERS.matcher(userInput).find()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid input");
            return;
        }

        // Sanifica l'input dell'utente
        String sanitizedInput = POLICY.sanitize(userInput);

        // Escape dell'output
        String escapedOutput = HtmlEscapers.htmlEscaper().escape(sanitizedInput);

        // Usa l'input sanificato e escaped nella tua applicazione
        request.setAttribute("sanitizedInput", escapedOutput);
        request.getRequestDispatcher("/result.jsp").forward(request, response);
    }
}
