package securfirstlesson.demo.configs;

import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class FilterThatCheckTokenOfEveryRequest extends GenericFilterBean {

    private AuthenticationManager authenticationManager;

    public FilterThatCheckTokenOfEveryRequest(AuthenticationManager manager) {
     this.authenticationManager = manager;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {


        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        String tiket = httpServletRequest.getHeader("token");
        if (tiket != null){
            String decodedTicket = Jwts.parser().setSigningKey("yes".getBytes())
                    .parseClaimsJws(tiket)
                    .getBody().getSubject();

            System.out.println(decodedTicket);

            String[] split = decodedTicket.split("-");
            String name = split[0];
            String password = split[1];

            Authentication authenticate = this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(name, password));
            if (authenticate.isAuthenticated()){
                SecurityContextHolder.getContext().setAuthentication(authenticate);
            }

            filterChain.doFilter(servletRequest, servletResponse);
        }
    }
}
