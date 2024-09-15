import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import javax.servlet.http.HttpSession;

@WebFilter("/*")
public class ContentSecurityPolicyFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // Get nonce
        String nonce = NonceGenerator.generateNonce();
         // Get or create the session
            HttpSession session = request.getSession(false);  // Creates a session if it doesn't exist
        if (session != null) {
        session.setAttribute("cspNonce", nonce);
        }

        // Set CSP header
       String cspHeader = "default-src 'self'; " +
                   "script-src 'self' 'nonce-" + nonce + "'; " +
                   "script-src-attr 'self' 'nonce-" + nonce + "'; " +
                   "script-src-elem 'self' 'nonce-" + nonce + "'; " +
                   "style-src 'self' 'nonce-" + nonce + "'; " +
                   "img-src 'self' data:; " +
                   "font-src 'self' data: https://fonts.googleapis.com https://fonts.gstatic.com;";


        response.setHeader("Content-Security-Policy", cspHeader);

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
    }
}
