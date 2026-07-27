package com.nyberg.iam.domain;

import jakarta.persistence.*;
import lombok.*;

import java.util.UUID;

@Entity
@Table(name = "roles", schema = "iam")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 64)
    private String name;

    /** org | tenant | global */
    @Column(nullable = false, length = 16)
    private String scope;

    /** JWT claim value, e.g. org:admin */
    @Column(nullable = false, unique = true, length = 64)
    private String claim;

    @Column
    private String description;
}
