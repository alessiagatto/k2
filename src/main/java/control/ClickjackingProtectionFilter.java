package control;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ClickjackingProtectionFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Inizializzazione del filtro, se necessaria
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (response instanceof HttpServletResponse) {
            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
            // Aggiungi l'header X-Frame-Options per prevenire ClickJacking
            httpServletResponse.setHeader("X-Frame-Options", "DENY");
            // Aggiungi l'header Content-Security-Policy con la direttiva frame-ancestors
            httpServletResponse.setHeader("Content-Security-Policy", "frame-ancestors 'none'");
        }
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // Pulizia del filtro, se necessaria
    }
}

