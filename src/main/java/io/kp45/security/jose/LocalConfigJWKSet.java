package io.kp45.security.jose;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.InitializingBean;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LocalConfigJWKSet implements JWKSource<SecurityContext>, InitializingBean {
    private JWKSet jwkSet;

    public LocalConfigJWKSet() {
        this.init();
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
        return jwkSelector.select(this.jwkSet);
    }

    public void rotate() {
        init();
    }

    private void init() {
        RSAKey rsaKey = Jwks.generateRsa();
        this.jwkSet = new JWKSet(Arrays.asList(rsaKey));
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        this.init();
    }
}
