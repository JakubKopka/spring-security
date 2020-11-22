package pl.kopka.springsecurity.model;

import com.sun.istack.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.validator.constraints.UniqueElements;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import javax.validation.constraints.Pattern;
import java.util.*;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AppUser implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @Column(unique = true)
    private String username;

    @NotNull
    private String password;

    private boolean isEnabled;

    @NotNull
    @Column(unique = true)
    @Pattern(regexp = "^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$")
    private String mail;

    @ManyToMany(fetch = FetchType.EAGER)
    private Set<AppRole> appRoles = new HashSet<>();

    @Transient
    private String rememberMeValue;

    public AppUser(String username, String password, boolean isEnabled, @Pattern(regexp = "^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$") String mail) {
        this.username = username;
        this.password = password;
        this.isEnabled = isEnabled;
        this.mail = mail;
    }

    public void addRole(AppRole appRole){
        this.appRoles.add(appRole);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return appRoles;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }
}
